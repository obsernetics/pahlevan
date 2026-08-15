package visualization

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sampleData builds a two-node, one-edge graph. Two nodes is the smallest
// graph that can expose an ordering bug, which is the failure mode these
// exporters are most prone to.
func sampleData() *AttackSurfaceData {
	return &AttackSurfaceData{
		Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ClusterGraph: &ClusterAttackSurfaceGraph{
			Nodes: map[string]*AttackSurfaceNode{
				"pod/prod/api": {
					ID: "pod/prod/api", Name: "api", Namespace: "prod",
					Type: NodeTypePod, RiskScore: 8.5,
					CriticalityLevel:   CriticalityCritical,
					Capabilities:       []string{"NET_BIND_SERVICE"},
					VulnerabilityCount: 3,
					ExposedPorts:       []*ExposedPort{{Port: 8080}},
				},
				"pod/prod/db": {
					ID: "pod/prod/db", Name: "db", Namespace: "prod",
					Type: NodeTypePod, RiskScore: 2.0,
					CriticalityLevel: CriticalityLow,
				},
			},
			Edges: map[string]*AttackSurfaceEdge{
				"e1": {
					ID: "e1", Source: "pod/prod/api", Target: "pod/prod/db",
					Type: EdgeTypeNetworkConnection, Protocol: "TCP", Weight: 1.5,
					RiskContribution: 0.4,
				},
			},
		},
	}
}

// The stub returned the literal string "graph TD" for every cluster. That is
// a valid Mermaid document, so it renders as an empty diagram and nothing about
// the output says the data never made it in.
func TestMermaidExportContainsTheGraph(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	out, err := asa.exportToMermaid(sampleData())
	require.NoError(t, err)
	s := string(out)

	assert.True(t, strings.HasPrefix(s, "graph TD\n"))
	assert.Contains(t, s, "prod/api")
	assert.Contains(t, s, "prod/db")
	assert.Contains(t, s, "risk 8.5")
	// The edge must connect the two sanitized node IDs and carry its protocol.
	assert.Contains(t, s, mermaidID("pod/prod/api")+" -->|TCP| "+mermaidID("pod/prod/db"))
	assert.NotEqual(t, "graph TD", strings.TrimSpace(s))
}

// A critical node gets a distinct shape, so severity survives a black-and-white
// render or a diff in a pull request.
func TestMermaidMarksCriticalNodes(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	out, err := asa.exportToMermaid(sampleData())
	require.NoError(t, err)
	s := string(out)

	assert.Contains(t, s, mermaidID("pod/prod/api")+`{{"`, "critical node uses the hexagon form")
	assert.Contains(t, s, mermaidID("pod/prod/db")+`["`, "a low-risk node stays a plain box")
}

// Map iteration order would otherwise make every export differ from the last,
// which destroys the main reason to export: diffing two snapshots.
func TestExportsAreDeterministic(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	for name, fn := range map[string]func(*AttackSurfaceData) ([]byte, error){
		"mermaid":   asa.exportToMermaid,
		"cytoscape": asa.exportToCytoscape,
		"graphql":   asa.exportToGraphQL,
	} {
		t.Run(name, func(t *testing.T) {
			var first string
			for i := 0; i < 20; i++ {
				out, err := fn(sampleData())
				require.NoError(t, err)
				if i == 0 {
					first = string(out)
					continue
				}
				assert.Equal(t, first, string(out), "export must not depend on map order")
			}
		})
	}
}

// Kubernetes IDs carry slashes and dots, which Mermaid parses as syntax.
func TestMermaidIDSanitisesSeparators(t *testing.T) {
	assert.Equal(t, "n_pod_prod_api", mermaidID("pod/prod/api"))
	assert.Equal(t, "n_a_b_c", mermaidID("a.b-c"))
	assert.Equal(t, "n", mermaidID(""), "an empty ID must still be a legal identifier")
	// Different IDs must not collide after sanitisation of the same length.
	assert.NotEqual(t, mermaidID("a/b"), mermaidID("ab"))
}

// A label containing a quote would otherwise terminate the Mermaid string and
// produce a document that does not parse at all.
func TestMermaidLabelEscapesQuotes(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	d := sampleData()
	d.ClusterGraph.Nodes["pod/prod/api"].Name = `we"ird`
	out, err := asa.exportToMermaid(d)
	require.NoError(t, err)
	assert.NotContains(t, string(out), `we"ird`)
	assert.Contains(t, string(out), `we'ird`)
}

// An empty graph must say so rather than emit a valid-but-blank diagram, which
// reads as "nothing is exposed" when it usually means "nothing was analyzed".
func TestMermaidEmptyGraphIsExplicit(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	out, err := asa.exportToMermaid(&AttackSurfaceData{ClusterGraph: &ClusterAttackSurfaceGraph{}})
	require.NoError(t, err)
	assert.Contains(t, string(out), "no attack surface data")
}

func TestCytoscapeExportIsLoadable(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	out, err := asa.exportToCytoscape(sampleData())
	require.NoError(t, err)

	var doc struct {
		Elements []struct {
			Group   string         `json:"group"`
			Data    map[string]any `json:"data"`
			Classes string         `json:"classes"`
		} `json:"elements"`
		Timestamp string `json:"timestamp"`
	}
	require.NoError(t, json.Unmarshal(out, &doc), "output must be the JSON Cytoscape.js loads")
	require.Len(t, doc.Elements, 3, "two nodes and one edge")
	assert.Equal(t, "2026-01-02T03:04:05Z", doc.Timestamp)

	var nodes, edges int
	for _, e := range doc.Elements {
		switch e.Group {
		case "nodes":
			nodes++
			assert.NotEmpty(t, e.Data["id"])
		case "edges":
			edges++
			// Cytoscape drops an edge whose endpoints are missing, so these two
			// fields are the difference between a graph and a scatter of dots.
			assert.NotEmpty(t, e.Data["source"])
			assert.NotEmpty(t, e.Data["target"])
		}
	}
	assert.Equal(t, 2, nodes)
	assert.Equal(t, 1, edges)
}

func TestGraphQLExportShape(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	out, err := asa.exportToGraphQL(sampleData())
	require.NoError(t, err)

	var doc struct {
		Data struct {
			AttackSurface struct {
				Timestamp string           `json:"timestamp"`
				Nodes     []map[string]any `json:"nodes"`
				Edges     []map[string]any `json:"edges"`
			} `json:"attackSurface"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Data.AttackSurface.Nodes, 2)
	require.Len(t, doc.Data.AttackSurface.Edges, 1)
	// Sorted by ID: api precedes db.
	assert.Equal(t, "pod/prod/api", doc.Data.AttackSurface.Nodes[0]["id"])
	assert.Equal(t, "2026-01-02T03:04:05Z", doc.Data.AttackSurface.Timestamp)
}

// An empty list must serialize as [] rather than null: a GraphQL client reading
// a non-null list field errors on null.
func TestGraphQLEmptyListsAreNotNull(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	out, err := asa.exportToGraphQL(&AttackSurfaceData{ClusterGraph: &ClusterAttackSurfaceGraph{}})
	require.NoError(t, err)
	assert.Contains(t, string(out), `"nodes": []`)
	assert.Contains(t, string(out), `"edges": []`)
}

// Every exporter must refuse nil rather than panic or emit a plausible-looking
// empty document.
func TestExportersRejectNilData(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	for name, fn := range map[string]func(*AttackSurfaceData) ([]byte, error){
		"mermaid":   asa.exportToMermaid,
		"cytoscape": asa.exportToCytoscape,
		"graphql":   asa.exportToGraphQL,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fn(nil)
			assert.Error(t, err)
		})
	}
}

// A nil ClusterGraph must not panic: the analyzer returns one before its first
// analysis completes.
func TestExportersTolerateANilGraph(t *testing.T) {
	asa := &AttackSurfaceAnalyzer{}
	assert.Nil(t, sortedNodes(nil))
	assert.Nil(t, sortedEdges(nil))
	for _, fn := range []func(*AttackSurfaceData) ([]byte, error){
		asa.exportToMermaid, asa.exportToCytoscape, asa.exportToGraphQL,
	} {
		_, err := fn(&AttackSurfaceData{})
		assert.NoError(t, err)
	}
}

// A nil entry in the map must be skipped, not dereferenced.
func TestSortedHelpersSkipNilEntries(t *testing.T) {
	g := &ClusterAttackSurfaceGraph{
		Nodes: map[string]*AttackSurfaceNode{"a": nil, "b": {ID: "b"}},
		Edges: map[string]*AttackSurfaceEdge{"a": nil, "b": {ID: "b"}},
	}
	require.Len(t, sortedNodes(g), 1)
	require.Len(t, sortedEdges(g), 1)
}

func BenchmarkExportToMermaid(b *testing.B) {
	asa := &AttackSurfaceAnalyzer{}
	d := largeGraph(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := asa.exportToMermaid(d); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExportToCytoscape(b *testing.B) {
	asa := &AttackSurfaceAnalyzer{}
	d := largeGraph(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := asa.exportToCytoscape(d); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExportToGraphQL(b *testing.B) {
	asa := &AttackSurfaceAnalyzer{}
	d := largeGraph(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := asa.exportToGraphQL(d); err != nil {
			b.Fatal(err)
		}
	}
}

func largeGraph(n int) *AttackSurfaceData {
	g := &ClusterAttackSurfaceGraph{
		Nodes: make(map[string]*AttackSurfaceNode, n),
		Edges: make(map[string]*AttackSurfaceEdge, n),
	}
	for i := 0; i < n; i++ {
		id := "pod/prod/workload-" + strings.Repeat("x", i%8) + itoa(i)
		g.Nodes[id] = &AttackSurfaceNode{
			ID: id, Name: "workload", Namespace: "prod",
			Type: NodeTypePod, RiskScore: float64(i % 10),
			CriticalityLevel: CriticalityMedium,
		}
		g.Edges["e"+itoa(i)] = &AttackSurfaceEdge{
			ID: "e" + itoa(i), Source: id, Target: id, Type: EdgeTypeNetworkConnection, Protocol: "TCP",
		}
	}
	return &AttackSurfaceData{ClusterGraph: g, Timestamp: time.Unix(0, 0).UTC()}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
