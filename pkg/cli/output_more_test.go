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

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func newBufWriter(format string) (*OutputWriter, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return &OutputWriter{Writer: buf, Format: OutputFormat(format)}, buf
}

func TestNewOutputWriter(t *testing.T) {
	w := NewOutputWriter("json")
	if w.Format != OutputFormatJSON {
		t.Errorf("format = %q, want json", w.Format)
	}
	if w.Writer == nil {
		t.Error("Writer should default to os.Stdout, got nil")
	}
}

func TestWriteObject_JSON(t *testing.T) {
	w, buf := newBufWriter("json")
	obj := map[string]string{"name": "web", "phase": "Enforcing"}
	if err := w.WriteObject(obj); err != nil {
		t.Fatalf("WriteObject json error: %v", err)
	}
	var round map[string]string
	if err := json.Unmarshal(buf.Bytes(), &round); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if round["name"] != "web" {
		t.Errorf("round-trip name = %q, want web", round["name"])
	}
}

func TestWriteObject_YAML(t *testing.T) {
	w, buf := newBufWriter("yaml")
	if err := w.WriteObject(map[string]int{"count": 3}); err != nil {
		t.Fatalf("WriteObject yaml error: %v", err)
	}
	if !strings.Contains(buf.String(), "count: 3") {
		t.Errorf("yaml output = %q, want count: 3", buf.String())
	}
}

func TestWriteObject_UnsupportedFormat(t *testing.T) {
	w, _ := newBufWriter("table")
	if err := w.WriteObject(struct{}{}); err == nil {
		t.Error("WriteObject should reject table format for single object")
	}
}

func TestWriteTable(t *testing.T) {
	w, buf := newBufWriter("table")
	err := w.WriteTable([]string{"NAME", "PHASE"}, [][]string{{"web", "Enforcing"}, {"db", "Learning"}})
	if err != nil {
		t.Fatalf("WriteTable error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"NAME", "PHASE", "web", "Enforcing", "db", "Learning"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q: %q", want, out)
		}
	}
}

func TestWriteTable_WideFormatAllowed(t *testing.T) {
	w, _ := newBufWriter("wide")
	if err := w.WriteTable([]string{"A"}, [][]string{{"1"}}); err != nil {
		t.Errorf("WriteTable should support wide format: %v", err)
	}
}

func TestWriteTable_RejectsNonTableFormat(t *testing.T) {
	w, _ := newBufWriter("json")
	if err := w.WriteTable([]string{"A"}, nil); err == nil {
		t.Error("WriteTable should reject json format")
	}
}

func TestWriteTable_EmptyHeaders(t *testing.T) {
	w, buf := newBufWriter("table")
	if err := w.WriteTable(nil, [][]string{{"only-row"}}); err != nil {
		t.Fatalf("WriteTable error: %v", err)
	}
	if !strings.Contains(buf.String(), "only-row") {
		t.Errorf("expected row output, got %q", buf.String())
	}
}

func TestWriteList(t *testing.T) {
	w, buf := newBufWriter("json")
	if err := w.WriteList([]interface{}{"a", "b"}); err != nil {
		t.Fatalf("WriteList json error: %v", err)
	}
	if !strings.Contains(buf.String(), "a") || !strings.Contains(buf.String(), "b") {
		t.Errorf("list output = %q", buf.String())
	}

	wy, bufy := newBufWriter("yaml")
	if err := wy.WriteList([]interface{}{1, 2}); err != nil {
		t.Fatalf("WriteList yaml error: %v", err)
	}
	if bufy.Len() == 0 {
		t.Error("expected yaml list output")
	}

	wt, _ := newBufWriter("table")
	if err := wt.WriteList(nil); err == nil {
		t.Error("WriteList should reject table format")
	}
}

func TestPrintHelpers(t *testing.T) {
	cases := []struct {
		name string
		fn   func(w *OutputWriter, msg string)
		icon string
	}{
		{"success", (*OutputWriter).PrintSuccess, "✓"},
		{"error", (*OutputWriter).PrintError, "✗"},
		{"warning", (*OutputWriter).PrintWarning, "⚠"},
		{"info", (*OutputWriter).PrintInfo, "ℹ"},
	}
	for _, c := range cases {
		w, buf := newBufWriter("table")
		c.fn(w, "hello")
		out := buf.String()
		if !strings.Contains(out, c.icon) || !strings.Contains(out, "hello") {
			t.Errorf("%s: output = %q, want icon %q + message", c.name, out, c.icon)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	cases := map[time.Duration]string{
		30 * time.Second: "30s",
		5 * time.Minute:  "5m",
		2 * time.Hour:    "2.0h",
		48 * time.Hour:   "2.0d",
	}
	for d, want := range cases {
		if got := FormatDuration(d); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestFormatTimestamp(t *testing.T) {
	if got := FormatTimestamp(time.Time{}); got != "<none>" {
		t.Errorf("zero timestamp = %q, want <none>", got)
	}
	recent := FormatTimestamp(time.Now().Add(-5 * time.Minute))
	if !strings.Contains(recent, "ago") {
		t.Errorf("recent timestamp = %q, want ...ago", recent)
	}
	old := time.Now().Add(-72 * time.Hour)
	got := FormatTimestamp(old)
	if strings.Contains(got, "ago") {
		t.Errorf("old timestamp %q should be absolute, not relative", got)
	}
	if _, err := time.Parse("2006-01-02 15:04:05", got); err != nil {
		t.Errorf("old timestamp %q not in expected absolute format", got)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{
		512:             "512 B",
		1024:            "1.0 KiB",
		1024 * 1024:     "1.0 MiB",
		5 * 1024 * 1024: "5.0 MiB",
		1024 * 1024 * 3: "3.0 MiB",
		1073741824:      "1.0 GiB",
	}
	for in, want := range cases {
		if got := FormatBytes(in); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatPercentage(t *testing.T) {
	if got := FormatPercentage(0.5); got != "50.0%" {
		t.Errorf("FormatPercentage(0.5) = %q, want 50.0%%", got)
	}
	if got := FormatPercentage(1.0); got != "100.0%" {
		t.Errorf("FormatPercentage(1.0) = %q, want 100.0%%", got)
	}
}

func TestFormatList(t *testing.T) {
	if got := FormatList(nil); got != "<none>" {
		t.Errorf("empty list = %q, want <none>", got)
	}
	if got := FormatList([]string{"a", "b"}); got != "a, b" {
		t.Errorf("short list = %q, want 'a, b'", got)
	}
	if got := FormatList([]string{"a", "b", "c"}); got != "a, b, c" {
		t.Errorf("3-element list = %q", got)
	}
	got := FormatList([]string{"a", "b", "c", "d", "e"})
	if !strings.Contains(got, "a, b, c") || !strings.Contains(got, "+ 2 more") {
		t.Errorf("long list = %q, want truncated with '+ 2 more'", got)
	}
}

func TestTruncateString(t *testing.T) {
	cases := []struct {
		in     string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly-ten", 11, "exactly-ten"},
		{"this is long", 8, "this ..."},
		{"abcdef", 3, "abc"},
		{"abcdef", 2, "ab"},
	}
	for _, c := range cases {
		if got := TruncateString(c.in, c.maxLen); got != c.want {
			t.Errorf("TruncateString(%q, %d) = %q, want %q", c.in, c.maxLen, got, c.want)
		}
	}
}

func TestStatusIcon(t *testing.T) {
	cases := map[string]string{
		"Ready":         "✓",
		"enforcing":     "✓",
		"Learning":      "◐",
		"pending":       "◐",
		"Failed":        "✗",
		"blocked":       "✗",
		"warning":       "⚠",
		"degraded":      "⚠",
		"unknown":       "?",
		"":              "?",
		"somethingelse": "○",
	}
	for status, want := range cases {
		if got := StatusIcon(status); got != want {
			t.Errorf("StatusIcon(%q) = %q, want %q", status, got, want)
		}
	}
}

func TestColorizeStatus_PublicNoColorViaHelper(t *testing.T) {
	// colorFor covers the transitioning/rollingback cyan branch.
	if colorFor("transitioning") != ansiCyan || colorFor("rollingback") != ansiCyan {
		t.Error("transition-ish statuses should be cyan")
	}
}

func TestTableData(t *testing.T) {
	td := NewTableData("NAME", "AGE")
	if len(td.Headers) != 2 {
		t.Fatalf("headers = %v", td.Headers)
	}
	if len(td.Rows) != 0 {
		t.Fatalf("new table should have no rows")
	}
	td.AddRow("web", "5m")
	td.AddRow("db", "1h")
	if len(td.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(td.Rows))
	}

	w, buf := newBufWriter("table")
	if err := td.Render(w); err != nil {
		t.Fatalf("Render error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"NAME", "AGE", "web", "5m", "db", "1h"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered table missing %q: %q", want, out)
		}
	}
}
