package netpol

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/obsernetics/pahlevan/pkg/cycle"
)

// Observation is one workload's learned network baseline: the destinations the
// agents recorded while it was learning, and enough context to say what that
// baseline is worth.
type Observation struct {
	// Namespace and Workload identify the subject. Workload is spelled
	// "Deployment/web" - the owner, not the pod, because the pod name changes
	// on every rollout and a policy outlives one.
	Namespace string
	Workload  string

	// Pods names the pods the baseline was learned from. It is evidence about
	// how much of the workload was watched, not a selector: see Generate.
	Pods []string

	// Window is the learning window the baseline was collected over, and
	// Schedule the cron expression of the CronJob that governs the workload,
	// empty when there is none. Together they are what pkg/cycle needs to say
	// whether the window was long enough to have seen the workload's whole
	// rhythm - which decides whether a policy built from this baseline denies
	// the thing the workload exists to do.
	Window   time.Duration
	Schedule string

	// Destinations is the learned egress set.
	Destinations []Destination
}

// Destination is one learned egress address and port.
type Destination struct {
	IP       string
	Port     int32
	Protocol corev1.Protocol
}

// Key identifies a subject.
func (o Observation) Key() string { return o.Namespace + "/" + o.Workload }

// Options configure Generate.
type Options struct {
	// Roster is every pod in the namespaces being generated for. Without it
	// no selector can be checked against the pods it would also select, and
	// Generate emits no policy at all rather than an unchecked one.
	Roster Roster

	// Resolver maps a destination address to an identity. A nil Resolver is
	// allowed and means nothing resolves: every destination becomes an
	// ipBlock, and the report says so.
	Resolver Resolver

	// Egress and Ingress choose the directions. Both false means both, which
	// is what a caller that did not care meant.
	Egress  bool
	Ingress bool

	// NamePrefix prefixes every generated policy name. Empty uses
	// DefaultNamePrefix.
	NamePrefix string
}

// DefaultNamePrefix marks a generated policy as one a human reviewed rather
// than one the operator maintains. Nothing in Pahlevan reconciles these: they
// are a starting point handed to whoever owns the namespace.
const DefaultNamePrefix = "pahlevan-"

// Level ranks a finding by what it does to the policy.
type Level int

const (
	// LevelNote is context. The policy is sound; this explains a choice in it.
	LevelNote Level = iota
	// LevelWarn means the emitted policy does not mean exactly what the
	// evidence says, in a way the reviewer has to decide about.
	LevelWarn
	// LevelBlock means nothing was emitted, because emitting it would have
	// claimed more than was observed.
	LevelBlock
)

func (l Level) String() string {
	switch l {
	case LevelWarn:
		return "warn"
	case LevelBlock:
		return "blocked"
	default:
		return "note"
	}
}

// Finding is one thing a reviewer has to read before applying a policy.
type Finding struct {
	Level   Level
	Message string
}

// Subject is what Generate decided about one workload.
type Subject struct {
	Namespace string
	Workload  string

	// Policy is the generated policy's name, empty when none was emitted.
	Policy string
	// Selector is the podSelector the policy applies to.
	Selector Selector

	// Observed is how many learned destinations went in; Expressed how many
	// are covered by a rule that came out. The gap is the part of the
	// baseline this tool could not honestly write down.
	Observed  int
	Expressed int

	// EgressRules and IngressRules count what was emitted.
	EgressRules  int
	IngressRules int

	// Window is pkg/cycle's verdict on the learning window: long enough for
	// the workload's cycle, or capped below it. CycleErr holds a schedule
	// that could not be parsed, which leaves Window at the declared minimum.
	Window   cycle.Requirement
	CycleErr string

	Findings []Finding
}

// Blocked reports whether this subject produced no policy.
func (s Subject) Blocked() bool { return s.Policy == "" }

// Key identifies a subject.
func (s Subject) Key() string { return s.Namespace + "/" + s.Workload }

// Result is everything Generate produced.
type Result struct {
	// Policies are the manifests, in namespace and name order.
	Policies []networkingv1.NetworkPolicy
	// Subjects is one entry per Observation, in the same order, whether or
	// not a policy came out of it.
	Subjects []Subject
}

// Count returns how many findings at or above a level the whole run produced.
func (r Result) Count(at Level) int {
	n := 0
	for _, s := range r.Subjects {
		for _, f := range s.Findings {
			if f.Level >= at {
				n++
			}
		}
	}
	return n
}

// port is one observed protocol and port number.
type port struct {
	num   int32
	proto corev1.Protocol
}

// peerGroup collects everything observed towards one identity. The grouping
// unit is the identity, not the address: three replicas of the same Deployment
// are one peer, and one rule, because a replica is not something a policy can
// name.
type peerGroup struct {
	key      string
	kind     PeerKind
	resolved bool
	ns       string
	name     string
	workload string
	labels   map[string]string
	ips      []string
	ports    map[port]bool
	count    int
}

func (g *peerGroup) add(d Destination) {
	g.count++
	g.ports[port{num: d.Port, proto: protocolOf(d)}] = true
	for _, ip := range g.ips {
		if ip == d.IP {
			return
		}
	}
	g.ips = append(g.ips, d.IP)
}

// sortedPorts renders the group's ports as policy ports, in a stable order.
func (g *peerGroup) sortedPorts() []networkingv1.NetworkPolicyPort { return sortPorts(g.ports) }

// sortPorts renders a port set as policy ports. Stable order matters more than
// it sounds: an unsorted rule list makes every regeneration a diff, and a diff
// nobody can read is a review nobody does.
func sortPorts(set map[port]bool) []networkingv1.NetworkPolicyPort {
	list := make([]port, 0, len(set))
	for p := range set {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].num != list[j].num {
			return list[i].num < list[j].num
		}
		return list[i].proto < list[j].proto
	})
	out := make([]networkingv1.NetworkPolicyPort, 0, len(list))
	for _, p := range list {
		proto := p.proto
		num := intstr.FromInt32(p.num)
		out = append(out, networkingv1.NetworkPolicyPort{Protocol: &proto, Port: &num})
	}
	return out
}

// protocolOf defaults an unset protocol to TCP, which is what a
// NetworkPolicyPort with no protocol means. Leaving it unset would be shorter
// and would silently change what an observed UDP flow is allowed to do.
func protocolOf(d Destination) corev1.Protocol {
	if d.Protocol == "" {
		return corev1.ProtocolTCP
	}
	return d.Protocol
}

// dnsPort is the port whose absence from a baseline is the single most common
// way a generated egress policy takes a workload down. Name resolution happens
// before the connection the baseline recorded, so a baseline that captured the
// connection and not the lookup produces a policy that permits the destination
// and denies finding it.
const dnsPort = 53

// Generate turns observed baselines into NetworkPolicies.
//
// It emits one policy per subject, and it emits nothing for a subject whose
// pods cannot be named by a label set that selects them and only them. That is
// the whole design: a policy is a claim about what is permitted, and this only
// makes claims the evidence supports.
func Generate(obs []Observation, opt Options) Result {
	if !opt.Egress && !opt.Ingress {
		opt.Egress, opt.Ingress = true, true
	}
	if opt.NamePrefix == "" {
		opt.NamePrefix = DefaultNamePrefix
	}

	ordered := append([]Observation(nil), obs...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Key() < ordered[j].Key() })
	idx := newRosterIndex(opt.Roster)

	// First pass: who can be named at all. Ingress rules name another
	// subject's pods, so every subject's selector has to be settled before any
	// rule is built.
	subjects := make([]Subject, len(ordered))
	groups := make([][]*peerGroup, len(ordered))
	byKey := make(map[string]int, len(ordered))
	for i, o := range ordered {
		subjects[i] = newSubject(o, opt, idx)
		byKey[o.Key()] = i
	}
	for i, o := range ordered {
		groups[i] = groupDestinations(o, opt, &subjects[i])
	}

	// Second pass: who must accept whom. A learned egress flow to a pod of
	// workload W is the only evidence this tool has that W accepts anything at
	// all, because the agents record a connection at the end that made it.
	// That makes every ingress rule below a derivation, not an observation,
	// and the report says so in as many words.
	//
	// Keyed target -> source -> ports, so building a subject's ingress reads
	// only its own obligations rather than scanning every pair.
	obligations := map[int]map[int]map[port]bool{}
	if opt.Ingress {
		for i := range ordered {
			if !subjects[i].Selector.OK() {
				continue
			}
			for _, g := range groups[i] {
				if !g.resolved || g.workload == "" {
					continue
				}
				t, ok := byKey[g.ns+"/"+g.workload]
				if !ok || !subjects[t].Selector.OK() {
					continue
				}
				if obligations[t] == nil {
					obligations[t] = map[int]map[port]bool{}
				}
				if obligations[t][i] == nil {
					obligations[t][i] = map[port]bool{}
				}
				for p := range g.ports {
					obligations[t][i][p] = true
				}
			}
		}
	}

	res := Result{Subjects: make([]Subject, 0, len(ordered))}
	for i, o := range ordered {
		s := &subjects[i]
		if !s.Selector.OK() {
			// newSubject already recorded why. Nothing here can name these
			// pods, so nothing here can write a rule about them.
			res.Subjects = append(res.Subjects, *s)
			continue
		}

		var egress []networkingv1.NetworkPolicyEgressRule
		if opt.Egress {
			for _, g := range groups[i] {
				peer, ok := peerFor(g, idx, s)
				if !ok {
					continue
				}
				// One rule per peer. A rule's `to` and `ports` are a cross
				// product, so folding three peers and three ports into one
				// rule would permit nine combinations from three observations.
				egress = append(egress, networkingv1.NetworkPolicyEgressRule{
					To:    []networkingv1.NetworkPolicyPeer{peer},
					Ports: g.sortedPorts(),
				})
				s.Expressed += g.count
			}
		}

		var ingress []networkingv1.NetworkPolicyIngressRule
		sources := make([]int, 0, len(obligations[i]))
		for j := range obligations[i] {
			sources = append(sources, j)
		}
		sort.Ints(sources)
		for _, j := range sources {
			ingress = append(ingress, networkingv1.NetworkPolicyIngressRule{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: namespaceSelector(subjects[j].Namespace),
					PodSelector:       &metav1.LabelSelector{MatchLabels: copyLabels(subjects[j].Selector.Labels)},
				}},
				Ports: sortPorts(obligations[i][j]),
			})
			s.Findings = append(s.Findings, Finding{LevelWarn, fmt.Sprintf(
				"ingress from %s is derived from that workload's egress, not from anything observed arriving here; "+
					"any other client of %s was never observed and would be denied",
				subjects[j].Key(), s.Workload)})
		}

		s.EgressRules, s.IngressRules = len(egress), len(ingress)
		// A subject with nothing to say gets no policy, with one exception:
		// a workload observed making no outbound connection at all. "Permit
		// nothing" is then the honest reading of the baseline rather than an
		// absence, and it is refused only when some of what was observed
		// could not be written down - a policy narrower than the evidence is
		// how this tool would take a workload down.
		if len(egress) == 0 && len(ingress) == 0 {
			switch {
			case opt.Egress && s.Observed == 0:
				// fall through and emit a deny-all-egress policy
			case opt.Egress && s.Observed > 0:
				// Egress was asked for and every destination fell out of it.
				s.Findings = append(s.Findings, Finding{LevelBlock, fmt.Sprintf(
					"all %d learned destinations were dropped, so the only policy left to generate would deny "+
						"traffic that was observed happening. None was generated", s.Observed)})
				res.Subjects = append(res.Subjects, *s)
				continue
			default:
				s.Findings = append(s.Findings, Finding{LevelBlock,
					"nothing about this workload could be expressed as a rule, so no policy was generated"})
				res.Subjects = append(res.Subjects, *s)
				continue
			}
		}

		s.Findings = append(s.Findings, consequences(s, opt, egress, ingress)...)
		s.Policy = policyName(opt.NamePrefix, o.Workload)
		res.Policies = append(res.Policies, policyFor(*s, o, egress, ingress, opt))
		res.Subjects = append(res.Subjects, *s)
	}

	sort.SliceStable(res.Policies, func(i, j int) bool {
		if res.Policies[i].Namespace != res.Policies[j].Namespace {
			return res.Policies[i].Namespace < res.Policies[j].Namespace
		}
		return res.Policies[i].Name < res.Policies[j].Name
	})
	return res
}

// newSubject settles whether a workload's pods can be named, which decides
// whether anything at all is emitted for it.
func newSubject(o Observation, opt Options, idx *rosterIndex) Subject {
	s := Subject{
		Namespace: o.Namespace,
		Workload:  o.Workload,
		Observed:  len(o.Destinations),
	}

	req, err := cycle.Required(o.Window, o.Schedule)
	s.Window = req
	if err != nil {
		s.CycleErr = err.Error()
	}

	// The set a selector has to name is the workload, not the pods that
	// happened to be watched: replicas are interchangeable, and a selector
	// that named one replica would stop matching the moment it rescheduled.
	want, sel := idx.workloadSelector(o.Namespace, o.Workload)
	if len(want) == 0 {
		// The workload is gone from the roster, or the agent never determined
		// an owner. The pods the baseline names are still evidence.
		for _, name := range o.Pods {
			if p, ok := idx.named(o.Namespace, name); ok {
				want = append(want, p)
			}
		}
		if len(want) > 0 {
			sel = selectorFor(want, idx.inNamespace(o.Namespace))
		}
	}
	if len(want) == 0 {
		s.Findings = append(s.Findings, Finding{LevelBlock, fmt.Sprintf(
			"no pod of %s is in the roster, so there is nothing to derive a podSelector from "+
				"and nothing to check one against", o.Key())})
		return s
	}

	s.Selector = sel
	if !s.Selector.OK() {
		s.Findings = append(s.Findings, Finding{LevelBlock, s.Selector.Reason()})
		if len(s.Selector.Volatile) > 0 {
			s.Findings = append(s.Findings, Finding{LevelNote, fmt.Sprintf(
				"%s was dropped from the candidate selector because a controller rewrites it; "+
					"a policy naming it would select nothing after the next rollout",
				strings.Join(s.Selector.Volatile, ", "))})
		}
		return s
	}

	// Naming the workload is right, and it still selects more pods than were
	// watched when only some replicas were. That widens what the policy
	// enforces on, not what it permits, so it is a warning rather than a
	// refusal - but it is the reviewer's call, not this tool's.
	if watched := len(o.Pods); watched > 0 && watched < len(want) {
		s.Findings = append(s.Findings, Finding{LevelWarn, fmt.Sprintf(
			"the baseline was learned from %d of this workload's %d pods; the policy selects all %d, "+
				"so %d pod(s) will be enforced on evidence that is not theirs",
			watched, len(want), len(want), len(want)-watched)})
	}
	return s
}

// groupDestinations resolves every learned address and collects them by
// identity.
func groupDestinations(o Observation, opt Options, s *Subject) []*peerGroup {
	index := map[string]*peerGroup{}
	var order []string

	for _, d := range o.Destinations {
		var p Peer
		var ok bool
		if opt.Resolver != nil {
			p, ok = opt.Resolver.Lookup(d.IP)
		}
		key, group := classify(p, ok, d)
		g, seen := index[key]
		if !seen {
			g = group
			g.key = key
			g.ports = map[port]bool{}
			index[key] = g
			order = append(order, key)
		}
		g.add(d)
	}

	sort.Strings(order)
	out := make([]*peerGroup, 0, len(order))
	for _, k := range order {
		out = append(out, index[k])
	}
	return out
}

// classify decides which group a destination belongs to, which is the same
// decision as "what could this ever become in a policy".
func classify(p Peer, ok bool, d Destination) (string, *peerGroup) {
	if !ok {
		// Unresolved. Not external - the index did not say external, it said
		// nothing - and the difference matters to whoever reads the report.
		return "addr:" + d.IP, &peerGroup{kind: "", ips: nil}
	}
	switch p.Kind {
	case PeerPod:
		if p.Workload != "" {
			return "pod:" + p.Namespace + "/" + p.Workload,
				&peerGroup{kind: PeerPod, resolved: true, ns: p.Namespace, workload: p.Workload, name: p.Name, labels: p.Labels}
		}
		// A pod with no owner is its own unit. It is also a pod that will
		// never come back under that name, which the report says.
		return "bare:" + p.Namespace + "/" + p.Name,
			&peerGroup{kind: PeerPod, resolved: true, ns: p.Namespace, name: p.Name, labels: p.Labels}
	case PeerService:
		return "svc:" + p.Namespace + "/" + p.Name,
			&peerGroup{kind: PeerService, resolved: true, ns: p.Namespace, name: p.Name, labels: p.Labels}
	case PeerNode:
		return "node:" + p.Name,
			&peerGroup{kind: PeerNode, resolved: true, name: p.Name}
	default:
		return "ext:" + d.IP, &peerGroup{kind: PeerExternal, resolved: true, name: p.Name}
	}
}

// peerFor turns one group into a policy peer, or refuses and records why.
func peerFor(g *peerGroup, idx *rosterIndex, s *Subject) (networkingv1.NetworkPolicyPeer, bool) {
	switch g.kind {
	case PeerPod:
		want, sel := idx.workloadSelector(g.ns, g.workload)
		if len(want) == 0 {
			if p, ok := idx.named(g.ns, g.name); ok {
				want = []Pod{p}
				sel = selectorFor(want, idx.inNamespace(g.ns))
			}
		}
		if len(want) == 0 {
			s.Findings = append(s.Findings, Finding{LevelWarn, fmt.Sprintf(
				"%d flow(s) to %s: the peer resolved to a pod that is not in the roster, so no selector "+
					"could be checked and no rule was written", g.count, g.ns+"/"+peerName(g))})
			return networkingv1.NetworkPolicyPeer{}, false
		}
		if !sel.OK() {
			s.Findings = append(s.Findings, Finding{LevelBlock, fmt.Sprintf(
				"%d flow(s) to %s were dropped: %s", g.count, g.ns+"/"+peerName(g), sel.Reason())})
			return networkingv1.NetworkPolicyPeer{}, false
		}
		if len(want) > 1 {
			s.Findings = append(s.Findings, Finding{LevelNote, fmt.Sprintf(
				"%s resolves to a workload of %d pods; the rule permits all of them, because a replica "+
					"is not an identity a policy can name", g.ns+"/"+peerName(g), len(want))})
		}
		return networkingv1.NetworkPolicyPeer{
			NamespaceSelector: namespaceSelector(g.ns),
			PodSelector:       &metav1.LabelSelector{MatchLabels: copyLabels(sel.Labels)},
		}, true

	case PeerService:
		if len(g.labels) == 0 {
			s.Findings = append(s.Findings, Finding{LevelBlock, fmt.Sprintf(
				"%d flow(s) to Service %s/%s were dropped: the Service has no selector, so the pods behind "+
					"it cannot be named", g.count, g.ns, g.name)})
			return networkingv1.NetworkPolicyPeer{}, false
		}
		// The Service's own selector is used verbatim. Trimming it would
		// permit pods the Service does not front, and anything it selects is
		// by definition behind the Service, so there is no widening to check
		// for here - the fan-out is the Service's, not this tool's.
		behind := 0
		for _, p := range idx.inNamespace(g.ns) {
			if matches(g.labels, p.Labels) {
				behind++
			}
		}
		s.Findings = append(s.Findings, Finding{LevelNote, fmt.Sprintf(
			"a NetworkPolicy cannot name a Service, so %d flow(s) to %s/%s became a selector over the %d pod(s) "+
				"behind it", g.count, g.ns, g.name, behind)})
		return networkingv1.NetworkPolicyPeer{
			NamespaceSelector: namespaceSelector(g.ns),
			PodSelector:       &metav1.LabelSelector{MatchLabels: copyLabels(g.labels)},
		}, true

	case PeerNode:
		s.Findings = append(s.Findings, Finding{LevelWarn, fmt.Sprintf(
			"%d flow(s) to node %s became %s: NetworkPolicy has no node selector, so this rule is a literal "+
				"address and is wrong the day the node is replaced", g.count, g.name, strings.Join(cidrs(g.ips), ", "))})
		return ipBlockPeer(g.ips), true

	case PeerExternal:
		s.Findings = append(s.Findings, Finding{LevelNote, fmt.Sprintf(
			"%d flow(s) to %s are outside the cluster and became %s",
			g.count, orUnnamed(g.name), strings.Join(cidrs(g.ips), ", "))})
		return ipBlockPeer(g.ips), true

	default:
		s.Findings = append(s.Findings, Finding{LevelWarn, fmt.Sprintf(
			"%d flow(s) to %s could not be resolved to any identity and became a literal address; "+
				"if that address is reassigned the rule permits whatever holds it next",
			g.count, strings.Join(g.ips, ", "))})
		return ipBlockPeer(g.ips), true
	}
}

func peerName(g *peerGroup) string {
	if g.workload != "" {
		return g.workload
	}
	return g.name
}

func orUnnamed(s string) string {
	if s == "" {
		return "an unnamed external address"
	}
	return s
}

// ipBlockPeer renders addresses as single-host CIDRs. A wider block would
// permit addresses nobody observed, and widening an ipBlock is exactly the
// silent generalisation this package refuses to make.
func ipBlockPeer(ips []string) networkingv1.NetworkPolicyPeer {
	list := cidrs(ips)
	if len(list) == 0 {
		return networkingv1.NetworkPolicyPeer{}
	}
	return networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: list[0]}}
}

// cidrs turns addresses into host CIDRs, /32 for IPv4 and /128 for IPv6.
func cidrs(ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			out = append(out, ip+"/128")
			continue
		}
		out = append(out, ip+"/32")
	}
	sort.Strings(out)
	return out
}

// namespaceSelector names one namespace by the label the API server sets on
// every namespace since 1.21. Without it a peer with only a podSelector means
// "in the policy's own namespace", which is a different and usually wrong rule.
func namespaceSelector(ns string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": ns}}
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// consequences states what applying the policy does, per subject. These are
// not diagnostics about the generation: they are what changes in the cluster.
func consequences(s *Subject, opt Options, egress []networkingv1.NetworkPolicyEgressRule,
	ingress []networkingv1.NetworkPolicyIngressRule,
) []Finding {
	var out []Finding

	if opt.Egress {
		if len(egress) == 0 {
			out = append(out, Finding{LevelWarn,
				"this workload was observed making no outbound connection at all, so the policy permits none. " +
					"Applying it denies every outbound connection these pods make from that moment on"})
		} else {
			out = append(out, Finding{LevelWarn, fmt.Sprintf(
				"applying this denies every outbound connection from these pods except the %d permitted here",
				len(egress))})
		}
		if !permitsDNS(egress) {
			out = append(out, Finding{LevelWarn,
				"no flow to port 53 is in this baseline, so the policy denies DNS. Name resolution happens " +
					"before the connection the baseline recorded, so this is the usual way a generated egress " +
					"policy takes a workload down"})
		}
	}
	if opt.Ingress && len(ingress) > 0 {
		out = append(out, Finding{LevelWarn, fmt.Sprintf(
			"applying this denies every inbound connection to these pods except from the %d source(s) permitted here, "+
				"including clients outside the cluster and clients that were quiet during the learning window",
			len(ingress))})
	}

	if s.Window.Capped() {
		out = append(out, Finding{LevelWarn, fmt.Sprintf(
			"this workload fires on a %s cycle and the learning window is capped at %s, so the baseline cannot "+
				"contain a whole period. A policy generated from it denies whatever that period does",
			s.Window.Cycle.Round(time.Minute), s.Window.Window.Round(time.Minute))})
	} else if s.Window.Window > 0 {
		out = append(out, Finding{LevelNote, fmt.Sprintf(
			"the baseline covers a %s window, so anything this workload does less often than that is not in it "+
				"and this policy denies it", s.Window.Window.Round(time.Second))})
	}
	if s.CycleErr != "" {
		out = append(out, Finding{LevelWarn,
			"the governing schedule could not be read, so the learning window was not checked against it: " + s.CycleErr})
	}

	if s.Expressed < s.Observed {
		out = append(out, Finding{LevelWarn, fmt.Sprintf(
			"%d of %d learned destinations are not in this policy; applying it denies them",
			s.Observed-s.Expressed, s.Observed)})
	}
	return out
}

func permitsDNS(rules []networkingv1.NetworkPolicyEgressRule) bool {
	for _, r := range rules {
		for _, p := range r.Ports {
			if p.Port != nil && p.Port.IntValue() == dnsPort {
				return true
			}
		}
	}
	return false
}

// policyFor assembles the manifest.
func policyFor(s Subject, o Observation, egress []networkingv1.NetworkPolicyEgressRule,
	ingress []networkingv1.NetworkPolicyIngressRule, opt Options,
) networkingv1.NetworkPolicy {
	var types []networkingv1.PolicyType
	// policyTypes is the part that changes cluster behaviour. Naming a
	// direction here denies everything in that direction that no rule
	// permits, including when the rule list is empty - which is a real and
	// deliberate outcome for a workload observed making no connections.
	if opt.Ingress && len(ingress) > 0 {
		types = append(types, networkingv1.PolicyTypeIngress)
	}
	if opt.Egress {
		types = append(types, networkingv1.PolicyTypeEgress)
	}

	return networkingv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyName(opt.NamePrefix, o.Workload),
			Namespace: o.Namespace,
			Annotations: map[string]string{
				// Provenance, so the next reader knows this is a proposal
				// derived from observation and not something a controller
				// maintains. Nothing in Pahlevan reconciles these.
				"pahlevan.io/generated-from":        "observed baseline",
				"pahlevan.io/workload":              o.Workload,
				"pahlevan.io/observed-destinations": strconv.Itoa(s.Observed),
				"pahlevan.io/learning-window":       s.Window.Window.String(),
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: copyLabels(s.Selector.Labels)},
			PolicyTypes: types,
			Ingress:     ingress,
			Egress:      egress,
		},
	}
}

// policyName spells a workload as a DNS-1123 name.
func policyName(prefix, workload string) string {
	name := prefix + sanitize(workload)
	if len(name) > 253 {
		name = name[:253]
	}
	return strings.Trim(name, "-")
}

func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-.")
}
