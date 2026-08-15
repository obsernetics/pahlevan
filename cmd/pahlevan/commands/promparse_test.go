/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commands

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

const sampleExposition = `# HELP pahlevan_blocked_syscalls_total Total syscalls blocked by the enforcer
# TYPE pahlevan_blocked_syscalls_total counter
pahlevan_blocked_syscalls_total{container="web",syscall="ptrace"} 12
pahlevan_blocked_syscalls_total{container="api",syscall="mount"} 3
# HELP pahlevan_containers_tracked Containers currently tracked
# TYPE pahlevan_containers_tracked gauge
pahlevan_containers_tracked 42
# HELP pahlevan_syscall_processing_latency_seconds Latency of syscall processing
# TYPE pahlevan_syscall_processing_latency_seconds histogram
pahlevan_syscall_processing_latency_seconds_bucket{le="0.001"} 100
pahlevan_syscall_processing_latency_seconds_bucket{le="+Inf"} 120
pahlevan_syscall_processing_latency_seconds_sum 0.35
pahlevan_syscall_processing_latency_seconds_count 120
# HELP go_goroutines Number of goroutines
# TYPE go_goroutines gauge
go_goroutines 27
`

func familyByName(t *testing.T, families []promFamily, name string) promFamily {
	t.Helper()
	for _, f := range families {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("family %q not found in %v", name, familyNames(families))
	return promFamily{}
}

func familyNames(families []promFamily) []string {
	names := make([]string, 0, len(families))
	for _, f := range families {
		names = append(names, f.Name)
	}
	return names
}

func TestParsePrometheusText_HappyPath(t *testing.T) {
	families, err := parsePrometheusText(strings.NewReader(sampleExposition))
	if err != nil {
		t.Fatalf("parsePrometheusText: %v", err)
	}
	if len(families) != 4 {
		t.Fatalf("got %d families (%v), want 4", len(families), familyNames(families))
	}

	blocked := familyByName(t, families, "pahlevan_blocked_syscalls_total")
	if blocked.Type != "counter" {
		t.Errorf("type = %q, want counter", blocked.Type)
	}
	if blocked.Help != "Total syscalls blocked by the enforcer" {
		t.Errorf("help = %q", blocked.Help)
	}
	if len(blocked.Samples) != 2 {
		t.Fatalf("got %d samples, want 2", len(blocked.Samples))
	}
	if got := blocked.Samples[0].Value; got != 12 {
		t.Errorf("value = %v, want 12", got)
	}
	if got := blocked.Samples[0].LabelString(); got != `{container="web",syscall="ptrace"}` {
		t.Errorf("labels = %q", got)
	}

	gauge := familyByName(t, families, "pahlevan_containers_tracked")
	if len(gauge.Samples) != 1 || gauge.Samples[0].Value != 42 {
		t.Errorf("gauge samples = %+v", gauge.Samples)
	}
	if gauge.Samples[0].LabelString() != "" {
		t.Errorf("unlabelled sample rendered labels %q", gauge.Samples[0].LabelString())
	}

	// Histogram sub-series must group under the declaring family.
	hist := familyByName(t, families, "pahlevan_syscall_processing_latency_seconds")
	if len(hist.Samples) != 4 {
		t.Fatalf("histogram samples = %d, want 4", len(hist.Samples))
	}
	if hist.Type != "histogram" {
		t.Errorf("histogram type = %q", hist.Type)
	}
}

func TestParsePrometheusText_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		wantFamily string
		check      func(t *testing.T, families []promFamily)
	}{
		{
			name:  "empty input yields no families",
			input: "",
			check: func(t *testing.T, families []promFamily) {
				t.Helper()
				if len(families) != 0 {
					t.Errorf("got %d families, want 0", len(families))
				}
			},
		},
		{
			name:  "help and type without samples are dropped",
			input: "# HELP lonely_metric nothing here\n# TYPE lonely_metric gauge\n",
			check: func(t *testing.T, families []promFamily) {
				t.Helper()
				if len(families) != 0 {
					t.Errorf("got %d families (%v), want 0", len(families), familyNames(families))
				}
			},
		},
		{
			name:  "sample without metadata still parses",
			input: "bare_metric 7\n",
			check: func(t *testing.T, families []promFamily) {
				t.Helper()
				if len(families) != 1 || families[0].Samples[0].Value != 7 {
					t.Errorf("families = %+v", families)
				}
			},
		},
		{
			name:  "timestamps are captured",
			input: "with_ts{a=\"b\"} 1.5 1700000000000\n",
			check: func(t *testing.T, families []promFamily) {
				t.Helper()
				s := families[0].Samples[0]
				if s.Value != 1.5 || s.Timestamp != 1700000000000 {
					t.Errorf("sample = %+v", s)
				}
			},
		},
		{
			name:  "escaped label values are unescaped",
			input: `esc{path="/a\\b",msg="say \"hi\"",multi="x\ny"} 1` + "\n",
			check: func(t *testing.T, families []promFamily) {
				t.Helper()
				labels := families[0].Samples[0].Labels
				want := []string{`/a\b`, `say "hi"`, "x\ny"}
				for i, w := range want {
					if labels[i].Value != w {
						t.Errorf("label %d = %q, want %q", i, labels[i].Value, w)
					}
				}
				// Round trips back through the escaper.
				if got := families[0].Samples[0].LabelString(); !strings.Contains(got, `\"hi\"`) {
					t.Errorf("LabelString = %q", got)
				}
			},
		},
		{
			name:  "unknown escape is preserved verbatim",
			input: `esc{v="a\tb"} 1` + "\n",
			check: func(t *testing.T, families []promFamily) {
				t.Helper()
				if got := families[0].Samples[0].Labels[0].Value; got != `a\tb` {
					t.Errorf("value = %q", got)
				}
			},
		},
		{
			name:  "special float spellings",
			input: "a_nan NaN\na_inf +Inf\na_ninf -Inf\na_low_inf inf\n",
			check: func(t *testing.T, families []promFamily) {
				t.Helper()
				byName := map[string]float64{}
				for _, f := range families {
					byName[f.Name] = f.Samples[0].Value
				}
				if !math.IsNaN(byName["a_nan"]) {
					t.Errorf("a_nan = %v", byName["a_nan"])
				}
				if !math.IsInf(byName["a_inf"], 1) || !math.IsInf(byName["a_low_inf"], 1) {
					t.Errorf("inf parsing wrong: %v", byName)
				}
				if !math.IsInf(byName["a_ninf"], -1) {
					t.Errorf("a_ninf = %v", byName["a_ninf"])
				}
			},
		},
		{
			name:  "empty label set",
			input: "no_labels{} 3\n",
			check: func(t *testing.T, families []promFamily) {
				t.Helper()
				if families[0].Samples[0].LabelString() != "" {
					t.Errorf("labels = %q", families[0].Samples[0].LabelString())
				}
			},
		},
		{
			name:  "blank lines and unrelated comments are skipped",
			input: "\n# just a comment\n\nok_metric 1\n",
			check: func(t *testing.T, families []promFamily) {
				t.Helper()
				if len(families) != 1 || families[0].Name != "ok_metric" {
					t.Errorf("families = %v", familyNames(families))
				}
			},
		},
		{name: "missing value", input: "broken_metric\n", wantErr: true},
		{name: "non numeric value", input: "broken_metric abc\n", wantErr: true},
		{name: "bad timestamp", input: "broken_metric 1 xyz\n", wantErr: true},
		{name: "unterminated label set", input: `broken{a="b" 1` + "\n", wantErr: true},
		{name: "unterminated label value", input: `broken{a="b} 1` + "\n", wantErr: true},
		{name: "missing equals", input: `broken{a} 1` + "\n", wantErr: true},
		{name: "unquoted label value", input: `broken{a=b} 1` + "\n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			families, err := parsePrometheusText(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got families %v", familyNames(families))
				}
				if !strings.Contains(err.Error(), "line ") {
					t.Errorf("error should name the offending line: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, families)
			}
		})
	}
}

func TestParseComment(t *testing.T) {
	tests := []struct {
		line     string
		wantOK   bool
		wantName string
		wantKind string
		wantText string
	}{
		{line: "# HELP m some help", wantOK: true, wantName: "m", wantKind: "HELP", wantText: "some help"},
		{line: "# TYPE m COUNTER", wantOK: true, wantName: "m", wantKind: "TYPE", wantText: "counter"},
		{line: `# HELP m line\nbreak`, wantOK: true, wantName: "m", wantKind: "HELP", wantText: "line\nbreak"},
		{line: `# HELP m back\\slash`, wantOK: true, wantName: "m", wantKind: "HELP", wantText: `back\slash`},
		{line: "# HELP m", wantOK: true, wantName: "m", wantKind: "HELP", wantText: ""},
		{line: "# some other comment", wantOK: false},
		{line: "# HELP ", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			name, kind, text, ok := parseComment(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if name != tt.wantName || kind != tt.wantKind || text != tt.wantText {
				t.Errorf("got (%q, %q, %q)", name, kind, text)
			}
		})
	}
}

func TestFilterFamilies(t *testing.T) {
	families, err := parsePrometheusText(strings.NewReader(sampleExposition))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	tests := []struct {
		name   string
		filter string
		want   []string
	}{
		{
			name:   "empty filter keeps everything",
			filter: "",
			want:   []string{"pahlevan_blocked_syscalls_total", "pahlevan_containers_tracked", "pahlevan_syscall_processing_latency_seconds", "go_goroutines"},
		},
		{
			name:   "prefix filter",
			filter: "pahlevan_",
			want:   []string{"pahlevan_blocked_syscalls_total", "pahlevan_containers_tracked", "pahlevan_syscall_processing_latency_seconds"},
		},
		{
			name:   "substring filter",
			filter: "blocked",
			want:   []string{"pahlevan_blocked_syscalls_total"},
		},
		{
			name:   "no match",
			filter: "definitely_absent",
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := familyNames(filterFamilies(families, tt.filter))
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// A family whose declared name is the trimmed base must still be kept when the
// filter only matches the suffixed series names.
func TestFilterFamilies_MatchesOnSampleNames(t *testing.T) {
	families, err := parsePrometheusText(strings.NewReader(sampleExposition))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := filterFamilies(families, "_bucket")
	if len(got) != 1 {
		t.Fatalf("got %v, want the histogram family", familyNames(got))
	}
	if len(got[0].Samples) != 2 {
		t.Errorf("kept %d samples, want the 2 bucket series", len(got[0].Samples))
	}
	// Filtering must not mutate the input families.
	if len(familyByName(t, families, "pahlevan_syscall_processing_latency_seconds").Samples) != 4 {
		t.Error("filterFamilies mutated its input")
	}
}

func TestSortFamilies(t *testing.T) {
	families, err := parsePrometheusText(strings.NewReader(sampleExposition))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sortFamilies(families)
	for i := 1; i < len(families); i++ {
		if families[i-1].Name > families[i].Name {
			t.Fatalf("families not sorted: %v", familyNames(families))
		}
	}
	blocked := familyByName(t, families, "pahlevan_blocked_syscalls_total")
	if blocked.Samples[0].LabelString() > blocked.Samples[1].LabelString() {
		t.Errorf("samples not sorted: %+v", blocked.Samples)
	}
}

func TestFamilyBaseName(t *testing.T) {
	tests := map[string]string{
		"m_bucket": "m",
		"m_sum":    "m",
		"m_count":  "m",
		"m_total":  "m",
		"m":        "m",
	}
	for in, want := range tests {
		if got := familyBaseName(in); got != want {
			t.Errorf("familyBaseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatMetricValue(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{42, "42"},
		{-7, "-7"},
		{1.5, "1.5"},
		{0.000125, "0.000125"},
		{math.NaN(), "NaN"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
		{1e20, "1e+20"},
	}
	for _, tt := range tests {
		if got := formatMetricValue(tt.in); got != tt.want {
			t.Errorf("formatMetricValue(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEscapeLabelValue(t *testing.T) {
	if got := escapeLabelValue("plain"); got != "plain" {
		t.Errorf("plain value changed: %q", got)
	}
	if got := escapeLabelValue("a\"b\\c\nd"); got != `a\"b\\c\nd` {
		t.Errorf("escaped = %q", got)
	}
}

// --- benchmarks -----------------------------------------------------------

// benchExposition builds a realistically sized scrape: several hundred series
// across the metric shapes a component actually exports.
func benchExposition() string {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "# HELP pahlevan_bench_counter_%d A benchmark counter\n", i)
		fmt.Fprintf(&b, "# TYPE pahlevan_bench_counter_%d counter\n", i)
		for j := 0; j < 8; j++ {
			fmt.Fprintf(&b, "pahlevan_bench_counter_%d{namespace=\"ns-%d\",container=\"c-%d\",syscall=\"openat\"} %d\n", i, j, j, i*j)
		}
	}
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "# HELP pahlevan_bench_hist_%d A benchmark histogram\n", i)
		fmt.Fprintf(&b, "# TYPE pahlevan_bench_hist_%d histogram\n", i)
		for _, le := range []string{"0.001", "0.01", "0.1", "1", "+Inf"} {
			fmt.Fprintf(&b, "pahlevan_bench_hist_%d_bucket{le=\"%s\"} 100\n", i, le)
		}
		fmt.Fprintf(&b, "pahlevan_bench_hist_%d_sum 12.5\n", i)
		fmt.Fprintf(&b, "pahlevan_bench_hist_%d_count 100\n", i)
	}
	b.WriteString(sampleExposition)
	return b.String()
}

func BenchmarkParsePrometheusText(b *testing.B) {
	payload := benchExposition()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		families, err := parsePrometheusText(strings.NewReader(payload))
		if err != nil {
			b.Fatalf("parse: %v", err)
		}
		if len(families) == 0 {
			b.Fatal("no families parsed")
		}
	}
}

func BenchmarkParsePrometheusTextSmall(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(sampleExposition)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parsePrometheusText(strings.NewReader(sampleExposition)); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}

func BenchmarkFilterAndSortFamilies(b *testing.B) {
	families, err := parsePrometheusText(strings.NewReader(benchExposition()))
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filtered := filterFamilies(families, defaultMetricFilter)
		sortFamilies(filtered)
	}
}
