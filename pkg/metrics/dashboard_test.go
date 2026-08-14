package metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	// Imported for its init(), which registers the data-plane counters on the
	// controller-runtime registry. The dashboard graphs those too.
	_ "github.com/obsernetics/pahlevan/pkg/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const dashboardPath = "../../deploy/monitoring/grafana-dashboard.json"

// pahlevanMetric matches a pahlevan_* series name inside a PromQL expression.
var pahlevanMetric = regexp.MustCompile(`pahlevan_[a-z0-9_]+`)

// declaredMetricNames is every pahlevan_* series the code can emit: the
// policy-plane collectors at full detail, plus the data-plane counters that
// pkg/ebpf registers in its init().
func declaredMetricNames(t *testing.T) map[string]bool {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := NewManagerWithDetail(reg, reg, DetailHigh)

	names := map[string]bool{}
	collect := func(c prometheus.Collector) {
		ch := make(chan *prometheus.Desc, 16)
		go func() { c.Describe(ch); close(ch) }()
		for d := range ch {
			// Desc.String() embeds fqName: "the_name".
			if match := regexp.MustCompile(`fqName: "([^"]+)"`).FindStringSubmatch(d.String()); match != nil {
				names[match[1]] = true
			}
		}
	}
	for _, c := range m.boundedCollectors() {
		collect(c)
	}
	for _, c := range m.perContainerCollectors() {
		collect(c)
	}

	families, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	for _, f := range families {
		names[f.GetName()] = true
	}
	return names
}

func dashboardExprs(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(dashboardPath))
	require.NoError(t, err, "the dashboard must exist where the README says it does")

	var dash struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	require.NoError(t, json.Unmarshal(raw, &dash))

	var exprs []string
	for _, p := range dash.Panels {
		for _, tg := range p.Targets {
			if tg.Expr != "" {
				exprs = append(exprs, tg.Expr)
			}
		}
	}
	require.NotEmpty(t, exprs, "the dashboard should query something")
	return exprs
}

// A dashboard of panels querying metrics nobody records is worse than no
// dashboard: it reads as "nothing is happening" rather than "this is not
// wired up". Every pahlevan_* series the dashboard graphs must be one the
// code can actually emit.
func TestDashboardOnlyQueriesRealMetrics(t *testing.T) {
	declared := declaredMetricNames(t)
	require.NotEmpty(t, declared)

	var missing []string
	for _, expr := range dashboardExprs(t) {
		for _, name := range pahlevanMetric.FindAllString(expr, -1) {
			// Histogram queries address the generated _bucket/_sum/_count
			// series, which Prometheus derives from the base metric.
			base := name
			for _, suffix := range []string{"_bucket", "_sum", "_count"} {
				base = strings.TrimSuffix(base, suffix)
			}
			if !declared[base] && !declared[name] {
				missing = append(missing, name)
			}
		}
	}
	sort.Strings(missing)
	require.Empty(t, missing,
		"the dashboard queries metrics no collector declares: %v", missing)
}

// The dashboard is meant to work at the default detail level. Graphing a
// per-container series would show an empty panel on every normal install and
// would not survive fleet scale if it were switched on.
func TestDashboardAvoidsHighCardinalityMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewManagerWithDetail(reg, reg, DetailHigh)

	highCard := map[string]bool{}
	for _, c := range m.perContainerCollectors() {
		ch := make(chan *prometheus.Desc, 16)
		go func(c prometheus.Collector) { c.Describe(ch); close(ch) }(c)
		for d := range ch {
			if match := regexp.MustCompile(`fqName: "([^"]+)"`).FindStringSubmatch(d.String()); match != nil {
				highCard[match[1]] = true
			}
		}
	}

	var offenders []string
	for _, expr := range dashboardExprs(t) {
		for _, name := range pahlevanMetric.FindAllString(expr, -1) {
			base := name
			for _, suffix := range []string{"_bucket", "_sum", "_count"} {
				base = strings.TrimSuffix(base, suffix)
			}
			if highCard[base] {
				offenders = append(offenders, name)
			}
		}
	}
	sort.Strings(offenders)
	require.Empty(t, offenders,
		"the dashboard graphs series that only exist at --metrics-detail=high: %v", offenders)
}

// Every panel must query something, or it renders as a permanently empty box.
func TestDashboardPanelsAllQuery(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(dashboardPath))
	require.NoError(t, err)

	var dash struct {
		Panels []struct {
			Title   string `json:"title"`
			Type    string `json:"type"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	require.NoError(t, json.Unmarshal(raw, &dash))

	for _, p := range dash.Panels {
		if p.Type == "row" {
			continue
		}
		require.NotEmpty(t, p.Targets, "panel %q has no queries", p.Title)
		for _, tg := range p.Targets {
			require.NotEmpty(t, tg.Expr, "panel %q has an empty query", p.Title)
		}
	}
}
