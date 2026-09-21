package netpol

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"
)

// fakeResolver is the whole of what this package needs from pkg/netidentity,
// driven from a table. It is the reason the generator can be tested against a
// Service peer, a node peer and an address that resolves to nothing without a
// cluster or an informer anywhere near it.
type fakeResolver map[string]Peer

func (f fakeResolver) Lookup(ip string) (Peer, bool) {
	p, ok := f[ip]
	return p, ok
}

func pod(ns, name, ip, workload string, labels map[string]string) Pod {
	return Pod{Namespace: ns, Name: name, IP: ip, Workload: workload, Labels: labels}
}

// twoTierRoster is a namespace with two workloads whose labels differ, which
// is the case a selector can be derived for.
func twoTierRoster() Roster {
	return Roster{
		pod("prod", "web-1", "10.0.0.1", "Deployment/web", map[string]string{"app": "web", "tier": "front"}),
		pod("prod", "web-2", "10.0.0.2", "Deployment/web", map[string]string{"app": "web", "tier": "front"}),
		pod("prod", "api-1", "10.0.1.1", "Deployment/api", map[string]string{"app": "api", "tier": "back"}),
	}
}

func dest(ip string, port int32) Destination {
	return Destination{IP: ip, Port: port, Protocol: corev1.ProtocolTCP}
}

// ---------------------------------------------------------------- selectors

func TestSelectorNamesExactlyTheWorkload(t *testing.T) {
	r := twoTierRoster()
	s := selectorFor(r.WorkloadPods("prod", "Deployment/web"), r.InNamespace("prod"))

	require.True(t, s.OK(), "web's labels do not appear on any other pod, so they name it exactly")
	assert.Equal(t, map[string]string{"app": "web", "tier": "front"}, s.Labels)
	assert.Empty(t, s.Extra)
	assert.Equal(t, "app=web,tier=front", s.String())
}

func TestSelectorRefusesWhenItWouldSelectUnobservedPods(t *testing.T) {
	// The failure this package exists for. A debug deployment carries the same
	// app label as the workload that was watched, so any selector derived from
	// the watched pods also permits the debug pods. Nobody observed those.
	r := Roster{
		pod("prod", "api-1", "10.0.1.1", "Deployment/api", map[string]string{"app": "api"}),
		pod("prod", "debug-1", "10.0.1.9", "Deployment/api-debug", map[string]string{"app": "api", "debug": "true"}),
	}
	s := selectorFor(r.WorkloadPods("prod", "Deployment/api"), r.InNamespace("prod"))

	assert.False(t, s.OK(), "app=api also selects the debug pod, so it must not be written into a policy")
	assert.Equal(t, []string{"prod/debug-1"}, s.Extra)
	assert.Contains(t, s.Reason(), "prod/debug-1")
	assert.Contains(t, s.Reason(), "never observed")
}

func TestSelectorDropsLabelsAControllerRewrites(t *testing.T) {
	// pod-template-hash is unique per ReplicaSet. A policy naming it selects
	// the pods it was generated from and nothing after the next rollout, which
	// is a policy that silently stops enforcing.
	r := Roster{
		pod("prod", "web-1", "10.0.0.1", "Deployment/web",
			map[string]string{"app": "web", "pod-template-hash": "7c9b4"}),
	}
	s := selectorFor(r.WorkloadPods("prod", "Deployment/web"), r.InNamespace("prod"))

	require.True(t, s.OK())
	assert.Equal(t, map[string]string{"app": "web"}, s.Labels)
	assert.Equal(t, []string{"pod-template-hash"}, s.Volatile)
}

func TestSelectorNeedsALabelSharedByEveryPod(t *testing.T) {
	// A key on one replica and not the other cannot be in a selector that has
	// to select both.
	r := Roster{
		pod("prod", "web-1", "10.0.0.1", "Deployment/web", map[string]string{"app": "web"}),
		pod("prod", "web-2", "10.0.0.2", "Deployment/web", map[string]string{"role": "web"}),
	}
	s := selectorFor(r.WorkloadPods("prod", "Deployment/web"), r.InNamespace("prod"))

	assert.False(t, s.OK())
	assert.Empty(t, s.Labels)
	assert.Contains(t, s.Reason(), "share no durable label")
}

func TestSelectorOfNothingIsUnusable(t *testing.T) {
	s := selectorFor(nil, nil)
	assert.False(t, s.OK())
	assert.Equal(t, "<none>", s.String())
	assert.Contains(t, s.Reason(), "share no durable label")
	assert.Empty(t, Selector{Labels: map[string]string{"a": "b"}}.Reason())
}

// ----------------------------------------------------------------- roster

func TestRosterLookups(t *testing.T) {
	r := twoTierRoster()
	assert.Len(t, r.InNamespace("prod"), 3)
	assert.Empty(t, r.InNamespace("staging"))
	assert.Len(t, r.WorkloadPods("prod", "Deployment/web"), 2)
	assert.Empty(t, r.WorkloadPods("prod", ""), "a pod with no owner is not evidence about a workload")

	p, ok := r.Named("prod", "api-1")
	require.True(t, ok)
	assert.Equal(t, "prod/api-1", p.Key())
	_, ok = r.Named("prod", "gone")
	assert.False(t, ok)
}

func TestRosterResolverKnowsOnlyPodAddresses(t *testing.T) {
	res := NewRosterResolver(twoTierRoster())

	p, ok := res.Lookup("10.0.1.1")
	require.True(t, ok)
	assert.Equal(t, PeerPod, p.Kind)
	assert.Equal(t, "Deployment/api", p.Workload)

	_, ok = res.Lookup("10.96.0.10")
	assert.False(t, ok, "a Service address is not in a pod listing, so it must resolve to nothing")

	var nilResolver *RosterResolver
	_, ok = nilResolver.Lookup("10.0.0.1")
	assert.False(t, ok)
}

func TestRosterResolverKeepsTheFirstPodAtAnAddress(t *testing.T) {
	// Two pods at one address means the listing is stale. Taking the second
	// would attribute traffic to whichever the API server returned last.
	res := NewRosterResolver(Roster{
		pod("prod", "first", "10.0.0.1", "Deployment/web", nil),
		pod("prod", "second", "10.0.0.1", "Deployment/api", nil),
		pod("prod", "no-ip", "", "Deployment/api", nil),
	})
	p, ok := res.Lookup("10.0.0.1")
	require.True(t, ok)
	assert.Equal(t, "first", p.Name)
}

// ---------------------------------------------------------------- generate

func TestGenerateWritesWhatWasObserved(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace:    "prod",
		Workload:     "Deployment/web",
		Pods:         []string{"web-1", "web-2"},
		Window:       50 * time.Minute,
		Destinations: []Destination{dest("10.0.1.1", 8080), dest("10.0.1.1", 9090), dest("10.0.1.1", 53)},
	}}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})

	require.Len(t, res.Policies, 1)
	p := res.Policies[0]
	assert.Equal(t, "networking.k8s.io/v1", p.APIVersion)
	assert.Equal(t, "NetworkPolicy", p.Kind)
	assert.Equal(t, "pahlevan-deployment-web", p.Name)
	assert.Equal(t, "prod", p.Namespace)
	assert.Equal(t, map[string]string{"app": "web", "tier": "front"}, p.Spec.PodSelector.MatchLabels)
	assert.Equal(t, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, p.Spec.PolicyTypes)

	require.Len(t, p.Spec.Egress, 1, "three flows to one workload are one peer and one rule")
	rule := p.Spec.Egress[0]
	require.Len(t, rule.To, 1)
	assert.Equal(t, map[string]string{"app": "api", "tier": "back"}, rule.To[0].PodSelector.MatchLabels)
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "prod"},
		rule.To[0].NamespaceSelector.MatchLabels)
	require.Len(t, rule.Ports, 3)
	assert.Equal(t, 53, rule.Ports[0].Port.IntValue(), "ports are sorted so a regeneration is not a diff")
	assert.Equal(t, corev1.ProtocolTCP, *rule.Ports[0].Protocol)

	assert.Equal(t, 3, res.Subjects[0].Expressed)
	assert.Equal(t, "50m0s", p.Annotations["pahlevan.io/learning-window"])
}

func TestGenerateRefusesASelectorWiderThanTheEvidence(t *testing.T) {
	r := Roster{
		pod("prod", "api-1", "10.0.1.1", "Deployment/api", map[string]string{"app": "api"}),
		pod("prod", "debug-1", "10.0.1.9", "Deployment/api-debug", map[string]string{"app": "api", "debug": "true"}),
	}
	res := Generate([]Observation{{
		Namespace:    "prod",
		Workload:     "Deployment/api",
		Pods:         []string{"api-1"},
		Destinations: []Destination{dest("1.1.1.1", 443)},
	}}, Options{Roster: r, Egress: true})

	assert.Empty(t, res.Policies, "no policy at all is the right answer when the selector cannot be justified")
	require.Len(t, res.Subjects, 1)
	assert.True(t, res.Subjects[0].Blocked())
	assert.Equal(t, 1, res.Blocked())
	assert.Contains(t, findingsText(res.Subjects[0]), "prod/debug-1")
}

func TestGenerateDropsAPeerItCannotName(t *testing.T) {
	// The peer end of the same problem: the destination resolves to a pod
	// whose workload shares its labels with another workload, so permitting
	// it would permit the other one too.
	r := Roster{
		pod("prod", "web-1", "10.0.0.1", "Deployment/web", map[string]string{"app": "web"}),
		pod("prod", "api-1", "10.0.1.1", "Deployment/api", map[string]string{"app": "shared"}),
		pod("prod", "other-1", "10.0.1.2", "Deployment/other", map[string]string{"app": "shared"}),
	}
	res := Generate([]Observation{{
		Namespace:    "prod",
		Workload:     "Deployment/web",
		Pods:         []string{"web-1"},
		Destinations: []Destination{dest("10.0.1.1", 8080)},
	}}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})

	assert.Empty(t, res.Policies,
		"the only observed flow was dropped, so any policy would deny traffic that was seen happening")
	require.Len(t, res.Subjects, 1)
	text := findingsText(res.Subjects[0])
	assert.Contains(t, text, "prod/other-1")
	assert.Contains(t, text, "all 1 learned destinations were dropped")
}

func TestGenerateWritesUnresolvedAddressesAsIPBlocks(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace:    "prod",
		Workload:     "Deployment/web",
		Pods:         []string{"web-1", "web-2"},
		Destinations: []Destination{dest("203.0.113.7", 443), dest("2001:db8::1", 443)},
	}}, Options{Roster: r, Resolver: fakeResolver{}, Egress: true})

	require.Len(t, res.Policies, 1)
	blocks := []string{}
	for _, rule := range res.Policies[0].Spec.Egress {
		require.Len(t, rule.To, 1)
		require.NotNil(t, rule.To[0].IPBlock, "an address with no identity can only be a literal address")
		assert.Nil(t, rule.To[0].NamespaceSelector, "a subnet is not an identity and must never become a selector")
		blocks = append(blocks, rule.To[0].IPBlock.CIDR)
	}
	assert.ElementsMatch(t, []string{"203.0.113.7/32", "2001:db8::1/128"}, blocks)
	assert.Contains(t, findingsText(res.Subjects[0]), "could not be resolved to any identity")
}

func TestGenerateSeparatesExternalFromUnresolved(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace:    "prod",
		Workload:     "Deployment/web",
		Pods:         []string{"web-1", "web-2"},
		Destinations: []Destination{dest("203.0.113.7", 443)},
	}}, Options{
		Roster:   r,
		Resolver: fakeResolver{"203.0.113.7": {Kind: PeerExternal, Name: "api.example.com"}},
		Egress:   true,
	})

	require.Len(t, res.Policies, 1)
	require.NotNil(t, res.Policies[0].Spec.Egress[0].To[0].IPBlock)
	text := findingsText(res.Subjects[0])
	assert.Contains(t, text, "api.example.com")
	assert.Contains(t, text, "outside the cluster")
	assert.NotContains(t, text, "could not be resolved to any identity")
}

func TestGenerateTurnsAServiceIntoThePodsBehindIt(t *testing.T) {
	r := Roster{
		pod("prod", "web-1", "10.0.0.1", "Deployment/web", map[string]string{"app": "web"}),
		pod("db", "pg-0", "10.0.2.1", "StatefulSet/pg", map[string]string{"app": "postgres"}),
		pod("db", "pg-1", "10.0.2.2", "StatefulSet/pg", map[string]string{"app": "postgres"}),
	}
	res := Generate([]Observation{{
		Namespace:    "prod",
		Workload:     "Deployment/web",
		Pods:         []string{"web-1"},
		Destinations: []Destination{dest("10.96.0.5", 5432)},
	}}, Options{
		Roster: r,
		Resolver: fakeResolver{"10.96.0.5": {
			Kind: PeerService, Namespace: "db", Name: "postgres",
			Labels: map[string]string{"app": "postgres"},
		}},
		Egress: true,
	})

	require.Len(t, res.Policies, 1)
	to := res.Policies[0].Spec.Egress[0].To[0]
	assert.Equal(t, map[string]string{"app": "postgres"}, to.PodSelector.MatchLabels)
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "db"}, to.NamespaceSelector.MatchLabels)
	text := findingsText(res.Subjects[0])
	assert.Contains(t, text, "cannot name a Service")
	assert.Contains(t, text, "2 pod(s) behind it")
}

func TestGenerateDropsAServiceWithNoSelector(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace:    "prod",
		Workload:     "Deployment/web",
		Pods:         []string{"web-1", "web-2"},
		Destinations: []Destination{dest("10.96.0.5", 5432)},
	}}, Options{
		Roster:   r,
		Resolver: fakeResolver{"10.96.0.5": {Kind: PeerService, Namespace: "db", Name: "external"}},
		Egress:   true,
	})

	assert.Empty(t, res.Policies)
	assert.Contains(t, findingsText(res.Subjects[0]), "the Service has no selector")
}

func TestGenerateWarnsThatANodeCanOnlyBeAnAddress(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace:    "prod",
		Workload:     "Deployment/web",
		Pods:         []string{"web-1", "web-2"},
		Destinations: []Destination{dest("192.168.1.10", 10250)},
	}}, Options{
		Roster:   r,
		Resolver: fakeResolver{"192.168.1.10": {Kind: PeerNode, Name: "node-1"}},
		Egress:   true,
	})

	require.Len(t, res.Policies, 1)
	assert.Equal(t, "192.168.1.10/32", res.Policies[0].Spec.Egress[0].To[0].IPBlock.CIDR)
	assert.Contains(t, findingsText(res.Subjects[0]), "no node selector")
}

func TestGenerateDerivesIngressFromTheOtherEndsEgress(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{
		{
			Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
			Destinations: []Destination{dest("10.0.1.1", 8080)},
		},
		{Namespace: "prod", Workload: "Deployment/api", Pods: []string{"api-1"}},
	}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true, Ingress: true})

	require.Len(t, res.Policies, 2)
	api := res.Policies[0]
	require.Equal(t, "pahlevan-deployment-api", api.Name)
	require.Len(t, api.Spec.Ingress, 1)
	assert.Equal(t, map[string]string{"app": "web", "tier": "front"},
		api.Spec.Ingress[0].From[0].PodSelector.MatchLabels)
	assert.Equal(t, 8080, api.Spec.Ingress[0].Ports[0].Port.IntValue())
	assert.Contains(t, api.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)

	var apiSubject Subject
	for _, s := range res.Subjects {
		if s.Workload == "Deployment/api" {
			apiSubject = s
		}
	}
	assert.Contains(t, findingsText(apiSubject), "derived from that workload's egress")
	assert.Contains(t, findingsText(apiSubject), "would be denied")
}

func TestGenerateOmitsIngressWhenNotAsked(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{
		{
			Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
			Destinations: []Destination{dest("10.0.1.1", 8080)},
		},
		{
			Namespace: "prod", Workload: "Deployment/api", Pods: []string{"api-1"},
			Destinations: []Destination{dest("10.0.0.1", 80)},
		},
	}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})

	for _, p := range res.Policies {
		assert.Empty(t, p.Spec.Ingress)
		assert.NotContains(t, p.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
	}
}

func TestGenerateEmitsDenyAllEgressForAWorkloadThatMadeNoConnection(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/api", Pods: []string{"api-1"},
	}}, Options{Roster: r, Egress: true})

	require.Len(t, res.Policies, 1)
	assert.Empty(t, res.Policies[0].Spec.Egress)
	assert.Equal(t, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, res.Policies[0].Spec.PolicyTypes)
	assert.Contains(t, findingsText(res.Subjects[0]), "observed making no outbound connection at all")
}

func TestGenerateWarnsWhenDNSIsNotInTheBaseline(t *testing.T) {
	r := twoTierRoster()
	opts := Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true}

	without := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Destinations: []Destination{dest("10.0.1.1", 8080)},
	}}, opts)
	assert.Contains(t, findingsText(without.Subjects[0]), "denies DNS")

	with := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Destinations: []Destination{dest("10.0.1.1", 8080), dest("10.0.1.1", 53)},
	}}, opts)
	assert.NotContains(t, findingsText(with.Subjects[0]), "denies DNS")
}

func TestGenerateSurfacesTheLearningWindowVerdict(t *testing.T) {
	r := twoTierRoster()
	// A monthly CronJob. pkg/cycle caps the window it will wait for at a week,
	// so the baseline provably cannot contain a whole period.
	capped := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Window: time.Hour, Schedule: "0 0 1 * *",
		Destinations: []Destination{dest("10.0.1.1", 53)},
	}}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})

	require.Len(t, capped.Subjects, 1)
	assert.True(t, capped.Subjects[0].Window.Capped())
	assert.Contains(t, findingsText(capped.Subjects[0]), "cannot contain a whole period")

	plain := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Window:       30 * time.Minute,
		Destinations: []Destination{dest("10.0.1.1", 53)},
	}}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})
	assert.Contains(t, findingsText(plain.Subjects[0]), "30m0s window")
}

func TestGenerateReportsAnUnreadableSchedule(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Window: time.Hour, Schedule: "not a cron expression",
		Destinations: []Destination{dest("10.0.1.1", 53)},
	}}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})

	assert.NotEmpty(t, res.Subjects[0].CycleErr)
	assert.Contains(t, findingsText(res.Subjects[0]), "was not checked against it")
}

func TestGenerateWarnsWhenOnlySomeReplicasWereWatched(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1"},
		Destinations: []Destination{dest("10.0.1.1", 53)},
	}}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})

	assert.Contains(t, findingsText(res.Subjects[0]), "learned from 1 of this workload's 2 pods")
}

func TestGenerateNeedsARoster(t *testing.T) {
	// With no roster there is nothing to check a selector against, and an
	// unchecked selector is a guess. Emitting one would be the exact failure
	// this package exists to prevent.
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1"},
		Destinations: []Destination{dest("10.0.1.1", 8080)},
	}}, Options{Egress: true})

	assert.Empty(t, res.Policies)
	assert.Contains(t, findingsText(res.Subjects[0]), "is in the roster")
}

func TestGenerateFallsBackToTheNamedPodsWhenTheWorkloadIsGone(t *testing.T) {
	// A bare pod, or one whose owner the agent could not determine. It is
	// still a pod in the roster, so a selector can still be checked.
	r := Roster{pod("prod", "loose", "10.0.9.9", "", map[string]string{"app": "loose"})}
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Pod/loose", Pods: []string{"loose"},
		Destinations: []Destination{dest("1.1.1.1", 53)},
	}}, Options{Roster: r, Egress: true})

	require.Len(t, res.Policies, 1)
	assert.Equal(t, map[string]string{"app": "loose"}, res.Policies[0].Spec.PodSelector.MatchLabels)
}

func TestGenerateDefaultsToBothDirections(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{
		{Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
			Destinations: []Destination{dest("10.0.1.1", 8080)}},
		{Namespace: "prod", Workload: "Deployment/api", Pods: []string{"api-1"}},
	}, Options{Roster: r, Resolver: NewRosterResolver(r)})

	require.Len(t, res.Policies, 2)
	assert.NotEmpty(t, res.Policies[0].Spec.Ingress)
	assert.NotEmpty(t, res.Policies[1].Spec.Egress)
}

func TestGenerateIsDeterministic(t *testing.T) {
	// A generator whose output moves between runs makes every regeneration a
	// diff, and a diff nobody can read is a review nobody does.
	r := twoTierRoster()
	obs := []Observation{
		{Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
			Destinations: []Destination{dest("10.0.1.1", 9090), dest("203.0.113.7", 443), dest("10.0.1.1", 53)}},
		{Namespace: "prod", Workload: "Deployment/api", Pods: []string{"api-1"},
			Destinations: []Destination{dest("198.51.100.4", 443)}},
	}
	opts := Options{Roster: r, Resolver: NewRosterResolver(r)}

	first, err := Generate(obs, opts).YAML()
	require.NoError(t, err)
	for i := 0; i < 5; i++ {
		again, err := Generate(obs, opts).YAML()
		require.NoError(t, err)
		require.Equal(t, string(first), string(again))
	}
}

func TestGenerateDoesNotDependOnTheOrderTheBaselineArrivedIn(t *testing.T) {
	// Two agents reporting the same destinations in a different order must
	// produce the same manifest. Otherwise regenerating after a rollout is a
	// diff of reordered rules, and a diff nobody can read is a review nobody
	// does.
	r := twoTierRoster()
	opts := Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true}
	dests := []Destination{dest("10.0.1.1", 9090), dest("203.0.113.7", 443), dest("198.51.100.4", 53)}

	forward := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Destinations: dests,
	}}, opts)
	reversed := make([]Destination, len(dests))
	for i, d := range dests {
		reversed[len(dests)-1-i] = d
	}
	backward := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Destinations: reversed,
	}}, opts)

	a, err := forward.YAML()
	require.NoError(t, err)
	b, err := backward.YAML()
	require.NoError(t, err)
	assert.Equal(t, string(a), string(b))
}

func TestPolicyNamesAreValidAndStable(t *testing.T) {
	for _, tc := range []struct{ workload, want string }{
		{"Deployment/web", "pahlevan-deployment-web"},
		{"StatefulSet/pg_main", "pahlevan-statefulset-pg-main"},
		{"DaemonSet/node.exporter", "pahlevan-daemonset-node.exporter"},
		{"///", "pahlevan"},
	} {
		assert.Equal(t, tc.want, policyName(DefaultNamePrefix, tc.workload))
	}
	assert.LessOrEqual(t, len(policyName("x-", strings.Repeat("a", 400))), 253)
}

func TestProtocolDefaultsToTCP(t *testing.T) {
	assert.Equal(t, corev1.ProtocolTCP, protocolOf(Destination{}))
	assert.Equal(t, corev1.ProtocolUDP, protocolOf(Destination{Protocol: corev1.ProtocolUDP}))
}

func TestGenerateKeepsProtocolsApart(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Destinations: []Destination{
			{IP: "10.0.1.1", Port: 53, Protocol: corev1.ProtocolUDP},
			{IP: "10.0.1.1", Port: 53, Protocol: corev1.ProtocolTCP},
		},
	}}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})

	require.Len(t, res.Policies, 1)
	ports := res.Policies[0].Spec.Egress[0].Ports
	require.Len(t, ports, 2, "TCP/53 and UDP/53 are two observations, not one")
	assert.Equal(t, corev1.ProtocolTCP, *ports[0].Protocol)
	assert.Equal(t, corev1.ProtocolUDP, *ports[1].Protocol)
}

func TestLevelStrings(t *testing.T) {
	assert.Equal(t, "note", LevelNote.String())
	assert.Equal(t, "warn", LevelWarn.String())
	assert.Equal(t, "blocked", LevelBlock.String())
	assert.Equal(t, "note", Level(99).String())
}

// ------------------------------------------------------------------ report

func TestReportStatesTheConsequenceBeforeAnythingElse(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Destinations: []Destination{dest("10.0.1.1", 8080)},
	}}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})

	var b bytes.Buffer
	require.NoError(t, res.Report(&b))
	out := b.String()

	assert.Contains(t, out, "Nothing here has been applied")
	assert.Contains(t, out, "allow-only")
	assert.Contains(t, out, "pahlevan-deployment-web")
	assert.Contains(t, out, "app=web,tier=front")
	assert.Contains(t, out, "1 egress, 0 ingress")
	assert.Contains(t, out, "This command applies nothing")
	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, len(line), 80, "the report is read in a terminal: %q", line)
	}
}

func TestReportNamesAWorkloadThatProducedNothing(t *testing.T) {
	r := Roster{
		pod("prod", "api-1", "10.0.1.1", "Deployment/api", map[string]string{"app": "api"}),
		pod("prod", "debug-1", "10.0.1.9", "Deployment/api-debug", map[string]string{"app": "api", "x": "y"}),
	}
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/api", Pods: []string{"api-1"},
		Destinations: []Destination{dest("1.1.1.1", 443)},
	}}, Options{Roster: r, Egress: true})

	var b bytes.Buffer
	require.NoError(t, res.Report(&b))
	assert.Contains(t, b.String(), "policy          none")
	assert.Contains(t, b.String(), "1 workload(s) produced none")
}

func TestReportOfNothing(t *testing.T) {
	var b bytes.Buffer
	require.NoError(t, Result{}.Report(&b))
	assert.Contains(t, b.String(), "No learned network baseline to read")
}

func TestYAMLRoundTrips(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Destinations: []Destination{dest("10.0.1.1", 8080)},
	}}, Options{Roster: r, Resolver: NewRosterResolver(r), Egress: true})

	out, err := res.YAML()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(out), "# Generated by pahlevan netpol"))
	assert.Contains(t, string(out), "allow-only")

	docs := strings.Split(string(out), "---\n")
	require.Len(t, docs, 2)
	var back networkingv1.NetworkPolicy
	require.NoError(t, yaml.Unmarshal([]byte(docs[1]), &back))
	assert.Equal(t, "pahlevan-deployment-web", back.Name)
	assert.Equal(t, map[string]string{"app": "web", "tier": "front"}, back.Spec.PodSelector.MatchLabels)
}

func TestWrapTextIndentsAndWraps(t *testing.T) {
	got := wrapText("one two three four", 10, "  ")
	assert.Equal(t, "  one two\n  three\n  four", got)
	assert.Equal(t, "  x", wrapText("x", 2, "  "), "a width narrower than the indent gives up rather than looping")
	assert.Equal(t, "", wrapText("   ", 20, ""))
}

// -------------------------------------------------------------------- diff

func TestDiffOfIdenticalManifestsIsEmpty(t *testing.T) {
	assert.Nil(t, Diff("a\nb\nc\n", "a\nb\nc\n"))
	assert.Nil(t, Diff("", ""))
}

func TestDiffShowsTheReplacedLines(t *testing.T) {
	got := Diff("a\nb\nc\n", "a\nB\nc\n")
	var rendered []string
	for _, l := range got {
		rendered = append(rendered, l.String())
	}
	assert.Equal(t, []string{"  a", "- b", "+ B", "  c"}, rendered)
}

func TestDiffKeepsOnlyContextAroundAChange(t *testing.T) {
	old := strings.Repeat("same\n", 20) + "old\n"
	current := strings.Repeat("same\n", 20) + "new\n"
	got := Diff(old, current)

	assert.LessOrEqual(t, len(got), 2*diffContext+3, "a manifest is mostly unchanged and printing all of it is unreadable")
	assert.Equal(t, "  ...", got[0].String())
	assert.Equal(t, "- old", got[len(got)-2].String())
	assert.Equal(t, "+ new", got[len(got)-1].String())
}

func TestDiffHandlesPureInsertAndDelete(t *testing.T) {
	assert.Equal(t, []DiffLine{{'+', "a"}, {'+', "b"}}, Diff("", "a\nb"))
	assert.Equal(t, []DiffLine{{'-', "a"}, {'-', "b"}}, Diff("a\nb", ""))
}

func TestRenderChanges(t *testing.T) {
	out := RenderChanges([]Change{
		{Namespace: "prod", Name: "pahlevan-deployment-web", Created: true},
		{Namespace: "prod", Name: "pahlevan-deployment-api", Lines: Diff("a\n", "b\n")},
		{Namespace: "prod", Name: "pahlevan-deployment-db"},
	})
	assert.Contains(t, out, "+ prod/pahlevan-deployment-web is new")
	assert.Contains(t, out, "would be replaced")
	assert.Contains(t, out, "- a")
	assert.Contains(t, out, "1 policy(s) already match")

	assert.Equal(t, "Applying this would change nothing.\n", RenderChanges(nil))
	assert.True(t, Change{Created: true}.Changed())
	assert.False(t, Change{}.Changed())
}

// ------------------------------------------------------- remaining branches

func TestGenerateNamesABarePodPeer(t *testing.T) {
	// A destination that resolved to a pod with no owner. It is its own unit,
	// and it is also a pod that never comes back under that name.
	r := Roster{
		pod("prod", "web-1", "10.0.0.1", "Deployment/web", map[string]string{"app": "web"}),
		pod("prod", "loose", "10.0.9.9", "", map[string]string{"app": "loose"}),
	}
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1"},
		Destinations: []Destination{dest("10.0.9.9", 8080)},
	}}, Options{
		Roster:   r,
		Resolver: fakeResolver{"10.0.9.9": {Kind: PeerPod, Namespace: "prod", Name: "loose"}},
		Egress:   true,
	})

	require.Len(t, res.Policies, 1)
	assert.Equal(t, map[string]string{"app": "loose"},
		res.Policies[0].Spec.Egress[0].To[0].PodSelector.MatchLabels)
}

func TestGenerateDropsAPeerPodTheRosterHasNeverHeardOf(t *testing.T) {
	// The identity index and the pod listing were read at different moments.
	// A peer the roster does not have cannot be checked, so it is not written.
	r := Roster{pod("prod", "web-1", "10.0.0.1", "Deployment/web", map[string]string{"app": "web"})}
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1"},
		Destinations: []Destination{dest("10.0.5.5", 8080), dest("1.1.1.1", 53)},
	}}, Options{
		Roster:   r,
		Resolver: fakeResolver{"10.0.5.5": {Kind: PeerPod, Namespace: "prod", Name: "gone", Workload: "Deployment/gone"}},
		Egress:   true,
	})

	require.Len(t, res.Policies, 1)
	text := findingsText(res.Subjects[0])
	assert.Contains(t, text, "not in the roster")
	assert.Contains(t, text, "1 of 2 learned destinations are not in this policy")
	assert.Equal(t, 1, res.Subjects[0].Expressed)
}

func TestGenerateNotesAnUnnamedExternalAddress(t *testing.T) {
	r := twoTierRoster()
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1", "web-2"},
		Destinations: []Destination{dest("203.0.113.7", 443)},
	}}, Options{
		Roster:   r,
		Resolver: fakeResolver{"203.0.113.7": {Kind: PeerExternal}},
		Egress:   true,
	})
	assert.Contains(t, findingsText(res.Subjects[0]), "an unnamed external address")
}

func TestGenerateExplainsAVolatileOnlySelector(t *testing.T) {
	// The only label distinguishing these two workloads is one a controller
	// rewrites, so dropping it is what made the selector unsafe. Saying so is
	// the difference between a refusal somebody can act on and one they cannot.
	r := Roster{
		pod("prod", "api-1", "10.0.1.1", "Deployment/api",
			map[string]string{"app": "api", "pod-template-hash": "aaa"}),
		pod("prod", "api-canary", "10.0.1.2", "Deployment/api-canary",
			map[string]string{"app": "api", "pod-template-hash": "bbb"}),
	}
	res := Generate([]Observation{{
		Namespace: "prod", Workload: "Deployment/api", Pods: []string{"api-1"},
		Destinations: []Destination{dest("1.1.1.1", 443)},
	}}, Options{Roster: r, Egress: true})

	assert.Empty(t, res.Policies)
	text := findingsText(res.Subjects[0])
	assert.Contains(t, text, "prod/api-canary")
	assert.Contains(t, text, "pod-template-hash was dropped")
}

func TestGenerateIngressOnlySkipsWhatItCannotName(t *testing.T) {
	// Ingress only, and three subjects: one whose selector is unusable, one
	// whose peer is not a subject at all, and one that ends up with nothing to
	// say. None of them may produce a policy built on a guess.
	r := Roster{
		pod("prod", "web-1", "10.0.0.1", "Deployment/web", map[string]string{"app": "web"}),
		pod("prod", "amb-1", "10.0.0.5", "Deployment/amb", map[string]string{"app": "shared"}),
		pod("prod", "amb-2", "10.0.0.6", "Deployment/amb-2", map[string]string{"app": "shared"}),
		pod("prod", "out-1", "10.0.0.9", "Deployment/out", map[string]string{"app": "out"}),
	}
	res := Generate([]Observation{
		// Unusable selector: app=shared also selects amb-2.
		{Namespace: "prod", Workload: "Deployment/amb", Pods: []string{"amb-1"},
			Destinations: []Destination{dest("10.0.0.1", 80)}},
		// Names a workload that is not among the subjects, so there is
		// nothing to hang an ingress rule on.
		{Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1"},
			Destinations: []Destination{dest("10.0.0.9", 80)}},
	}, Options{Roster: r, Resolver: NewRosterResolver(r), Ingress: true})

	assert.Empty(t, res.Policies)
	assert.Equal(t, 2, res.Blocked())
	assert.Contains(t, findingsText(res.Subjects[1]),
		"nothing about this workload could be expressed as a rule")
}

func TestGeneratedPoliciesAreOrderedByNamespaceThenName(t *testing.T) {
	r := Roster{
		pod("staging", "web-1", "10.1.0.1", "Deployment/web", map[string]string{"app": "web"}),
		pod("prod", "web-1", "10.0.0.1", "Deployment/web", map[string]string{"app": "web"}),
	}
	res := Generate([]Observation{
		{Namespace: "staging", Workload: "Deployment/web", Pods: []string{"web-1"}},
		{Namespace: "prod", Workload: "Deployment/web", Pods: []string{"web-1"}},
	}, Options{Roster: r, Egress: true})

	require.Len(t, res.Policies, 2)
	assert.Equal(t, "prod", res.Policies[0].Namespace)
	assert.Equal(t, "staging", res.Policies[1].Namespace)
}

func TestPeerNameAndIPBlockEdges(t *testing.T) {
	assert.Equal(t, "Deployment/web", peerName(&peerGroup{workload: "Deployment/web", name: "web-1"}))
	assert.Equal(t, "web-1", peerName(&peerGroup{name: "web-1"}))
	assert.Equal(t, "a.example", orUnnamed("a.example"))
	assert.Equal(t, networkingv1.NetworkPolicyPeer{}, ipBlockPeer(nil),
		"no address is not an empty ipBlock, which would permit everything")
}

func TestCommonLabelsOfNothing(t *testing.T) {
	labels, volatile := commonLabels(nil)
	assert.Nil(t, labels)
	assert.Nil(t, volatile)
}

// --------------------------------------------------------------- helpers

func findingsText(s Subject) string {
	var b strings.Builder
	for _, f := range s.Findings {
		b.WriteString(f.Level.String())
		b.WriteString(": ")
		b.WriteString(f.Message)
		b.WriteString("\n")
	}
	return b.String()
}
