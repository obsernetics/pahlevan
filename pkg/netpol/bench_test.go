package netpol

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

// The generator runs over a whole cluster's learned baselines, in a CLI a
// person is waiting on. The costs worth watching are the two quadratic-looking
// ones: selectorFor scans a namespace per candidate, and Diff builds an LCS
// table per policy.

// benchCluster builds a cluster of workloads x replicas pods, each talking to
// every other workload, which is the worst realistic shape: a namespace where
// every selector has to be checked against every pod in it.
func benchCluster(workloads, replicas, peers int) (Roster, []Observation, Resolver) {
	var roster Roster
	for w := 0; w < workloads; w++ {
		for r := 0; r < replicas; r++ {
			roster = append(roster, Pod{
				Namespace: "prod",
				Name:      fmt.Sprintf("w%d-%d", w, r),
				IP:        fmt.Sprintf("10.%d.%d.%d", w/250, w%250, r+1),
				Workload:  fmt.Sprintf("Deployment/w%d", w),
				Labels:    map[string]string{"app": fmt.Sprintf("w%d", w), "tier": "back"},
			})
		}
	}
	resolver := NewRosterResolver(roster)

	obs := make([]Observation, 0, workloads)
	for w := 0; w < workloads; w++ {
		o := Observation{
			Namespace: "prod",
			Workload:  fmt.Sprintf("Deployment/w%d", w),
			Pods:      []string{fmt.Sprintf("w%d-0", w)},
			Window:    3000000000,
		}
		for p := 0; p < peers; p++ {
			target := (w + p + 1) % workloads
			o.Destinations = append(o.Destinations,
				dest(fmt.Sprintf("10.%d.%d.1", target/250, target%250), int32(8000+p)))
		}
		obs = append(obs, o)
	}
	return roster, obs, resolver
}

func BenchmarkGenerate(b *testing.B) {
	roster, obs, resolver := benchCluster(64, 3, 4)
	opt := Options{Roster: roster, Resolver: resolver, Egress: true, Ingress: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := Generate(obs, opt); len(got.Policies) == 0 {
			b.Fatal("the fixture produced no policies, so this benchmark measures nothing")
		}
	}
}

func BenchmarkGenerateEgressOnly(b *testing.B) {
	roster, obs, resolver := benchCluster(64, 3, 4)
	opt := Options{Roster: roster, Resolver: resolver, Egress: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Generate(obs, opt)
	}
}

func BenchmarkSelectorFor(b *testing.B) {
	roster, _, _ := benchCluster(64, 3, 0)
	want := roster.WorkloadPods("prod", "Deployment/w0")
	all := roster.InNamespace("prod")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !selectorFor(want, all).OK() {
			b.Fatal("the fixture's selectors are unusable, so this benchmark measures the refusal path")
		}
	}
}

func BenchmarkRosterResolverLookup(b *testing.B) {
	roster, _, resolver := benchCluster(64, 3, 0)
	ip := roster[len(roster)-1].IP
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := resolver.Lookup(ip); !ok {
			b.Fatal("miss")
		}
	}
}

func BenchmarkYAML(b *testing.B) {
	roster, obs, resolver := benchCluster(32, 2, 3)
	res := Generate(obs, Options{Roster: roster, Resolver: resolver, Egress: true})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := res.YAML(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReport(b *testing.B) {
	roster, obs, resolver := benchCluster(32, 2, 3)
	res := Generate(obs, Options{Roster: roster, Resolver: resolver, Egress: true, Ingress: true})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := res.Report(io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDiff(b *testing.B) {
	roster, obs, resolver := benchCluster(4, 2, 2)
	res := Generate(obs, Options{Roster: roster, Resolver: resolver, Egress: true})
	current, err := res.YAML()
	if err != nil {
		b.Fatal(err)
	}
	old := strings.Replace(string(current), "8000", "9999", 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(Diff(old, string(current))) == 0 {
			b.Fatal("the fixtures are identical, so this benchmark measures the early return")
		}
	}
}
