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
	"bufio"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// This file implements just enough of the Prometheus text exposition format to
// render a component's /metrics endpoint. It is deliberately self contained:
// github.com/prometheus/common is only an indirect dependency of this module
// and promoting it to a direct one would mean editing go.mod, which this
// change must not do.
//
// The grammar handled here is the one components actually emit:
//
//	# HELP <name> <help text>
//	# TYPE <name> <counter|gauge|histogram|summary|untyped>
//	<name>[{<label>="<value>",...}] <float> [<timestamp>]
//
// Label values honour the format's three escapes (\\, \", \n). Values may be
// Nan/Inf spellings. Anything unparseable is reported with its line number
// rather than silently dropped.

// promLabel is one label of a sample. Labels are kept as an ordered slice
// rather than a map so rendering is deterministic without re-sorting per line.
type promLabel struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// promSample is a single time series sample from the exposition text.
type promSample struct {
	Name      string      `json:"name"`
	Labels    []promLabel `json:"labels,omitempty"`
	Value     float64     `json:"value"`
	Timestamp int64       `json:"timestamp,omitempty"`
}

// LabelString renders the labels back into the {k="v",...} form.
func (s promSample) LabelString() string {
	if len(s.Labels) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, l := range s.Labels {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l.Name)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(l.Value))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// promFamily groups the samples that share a metric name together with the
// HELP and TYPE metadata declared for it.
type promFamily struct {
	Name    string       `json:"name"`
	Type    string       `json:"type,omitempty"`
	Help    string       `json:"help,omitempty"`
	Samples []promSample `json:"samples"`
}

// familyBaseName strips the suffixes that histogram and summary series carry,
// so _bucket/_sum/_count samples group under the family that declared them.
func familyBaseName(name string) string {
	for _, suffix := range []string{"_bucket", "_sum", "_count", "_total"} {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	return name
}

// parsePrometheusText parses the Prometheus text exposition format into metric
// families, preserving the order in which the families first appear.
func parsePrometheusText(r io.Reader) ([]promFamily, error) {
	scanner := bufio.NewScanner(r)
	// Start small and let bufio grow the buffer: a fixed 64KiB allocation
	// dominates the cost of parsing a small scrape. The cap still bounds a
	// pathological single line.
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)

	families := make([]*promFamily, 0, 16)
	index := make(map[string]*promFamily, 16)

	get := func(name string) *promFamily {
		if f, ok := index[name]; ok {
			return f
		}
		f := &promFamily{Name: name}
		index[name] = f
		families = append(families, f)
		return f
	}

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line[0] == '#' {
			name, kind, text, ok := parseComment(line)
			if !ok {
				continue
			}
			f := get(name)
			if kind == "HELP" {
				f.Help = text
			} else {
				f.Type = text
			}
			continue
		}

		sample, err := parseSampleLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		// A sample may arrive before or without its HELP/TYPE; attach it to the
		// declaring family when one exists, otherwise to its own name.
		target := sample.Name
		if _, declared := index[target]; !declared {
			if base := familyBaseName(sample.Name); base != sample.Name {
				if _, ok := index[base]; ok {
					target = base
				}
			}
		}
		f := get(target)
		f.Samples = append(f.Samples, sample)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read metrics: %w", err)
	}

	out := make([]promFamily, 0, len(families))
	for _, f := range families {
		if len(f.Samples) == 0 {
			// A HELP/TYPE block with no series carries no information here.
			continue
		}
		out = append(out, *f)
	}
	return out, nil
}

// parseComment recognises the two meaningful comment forms. Any other comment
// yields ok=false and is ignored.
func parseComment(line string) (name, kind, text string, ok bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "#"))
	switch {
	case strings.HasPrefix(rest, "HELP "):
		kind, rest = "HELP", strings.TrimPrefix(rest, "HELP ")
	case strings.HasPrefix(rest, "TYPE "):
		kind, rest = "TYPE", strings.TrimPrefix(rest, "TYPE ")
	default:
		return "", "", "", false
	}
	rest = strings.TrimLeft(rest, " ")
	name, text, _ = strings.Cut(rest, " ")
	if name == "" {
		return "", "", "", false
	}
	text = strings.TrimSpace(text)
	if kind == "TYPE" {
		text = strings.ToLower(text)
	} else {
		text = unescapeHelp(text)
	}
	return name, kind, text, true
}

// parseSampleLine parses one `name{labels} value [timestamp]` record.
func parseSampleLine(line string) (promSample, error) {
	var sample promSample

	nameEnd := strings.IndexAny(line, "{ \t")
	if nameEnd < 0 {
		return sample, fmt.Errorf("malformed sample %q: no value", line)
	}
	sample.Name = line[:nameEnd]
	if sample.Name == "" {
		return sample, fmt.Errorf("malformed sample %q: empty metric name", line)
	}
	rest := line[nameEnd:]

	if strings.HasPrefix(rest, "{") {
		labels, remainder, err := parseLabels(rest)
		if err != nil {
			return sample, err
		}
		sample.Labels = labels
		rest = remainder
	}

	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return sample, fmt.Errorf("malformed sample %q: no value", line)
	}
	value, err := parsePromFloat(fields[0])
	if err != nil {
		return sample, fmt.Errorf("malformed sample %q: %w", line, err)
	}
	sample.Value = value
	if len(fields) > 1 {
		ts, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return sample, fmt.Errorf("malformed sample %q: bad timestamp %q", line, fields[1])
		}
		sample.Timestamp = ts
	}
	return sample, nil
}

// parseLabels consumes a {k="v",...} block and returns the labels plus the
// remainder of the line.
func parseLabels(s string) ([]promLabel, string, error) {
	if len(s) == 0 || s[0] != '{' {
		return nil, s, fmt.Errorf("malformed label set %q", s)
	}
	i := 1
	var labels []promLabel
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			return nil, "", fmt.Errorf("malformed label set %q: unterminated", s)
		}
		if s[i] == '}' {
			return labels, s[i+1:], nil
		}

		nameStart := i
		for i < len(s) && s[i] != '=' && s[i] != '}' && s[i] != ',' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			return nil, "", fmt.Errorf("malformed label set %q: expected '=' after label name", s)
		}
		name := s[nameStart:i]
		i++ // consume '='
		if i >= len(s) || s[i] != '"' {
			return nil, "", fmt.Errorf("malformed label set %q: expected quoted value for %q", s, name)
		}
		i++ // consume opening quote

		var value strings.Builder
		closed := false
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case 'n':
					value.WriteByte('\n')
				case '\\':
					value.WriteByte('\\')
				case '"':
					value.WriteByte('"')
				default:
					value.WriteByte('\\')
					value.WriteByte(s[i+1])
				}
				i += 2
				continue
			}
			if c == '"' {
				closed = true
				i++
				break
			}
			value.WriteByte(c)
			i++
		}
		if !closed {
			return nil, "", fmt.Errorf("malformed label set %q: unterminated label value", s)
		}
		labels = append(labels, promLabel{Name: name, Value: value.String()})
	}
}

// parsePromFloat handles the format's spellings of the special values on top of
// the ordinary decimal and exponent forms.
func parsePromFloat(s string) (float64, error) {
	switch s {
	case "NaN", "nan", "Nan":
		return math.NaN(), nil
	case "+Inf", "Inf", "inf", "+inf":
		return math.Inf(1), nil
	case "-Inf", "-inf":
		return math.Inf(-1), nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("bad value %q", s)
	}
	return v, nil
}

// escapeLabelValue is the inverse of the label value unescaping above.
func escapeLabelValue(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 4)
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(v[i])
		}
	}
	return b.String()
}

// unescapeHelp applies the two escapes HELP text may carry.
func unescapeHelp(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case '\\':
				b.WriteByte('\\')
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// filterFamilies keeps the families whose name matches the filter. An empty
// filter keeps everything; otherwise a family matches when its name has the
// filter as a prefix or contains it as a substring, which covers both
// "pahlevan_" style prefixes and "blocked" style keyword searches.
func filterFamilies(families []promFamily, filter string) []promFamily {
	if filter == "" {
		return families
	}
	out := make([]promFamily, 0, len(families))
	for _, f := range families {
		if matchesMetricFilter(f.Name, filter) {
			out = append(out, f)
			continue
		}
		// The family name may be the trimmed base while the series carry the
		// _total/_bucket suffix; match on the samples too.
		var kept []promSample
		for _, s := range f.Samples {
			if matchesMetricFilter(s.Name, filter) {
				kept = append(kept, s)
			}
		}
		if len(kept) > 0 {
			copied := f
			copied.Samples = kept
			out = append(out, copied)
		}
	}
	return out
}

func matchesMetricFilter(name, filter string) bool {
	return strings.HasPrefix(name, filter) || strings.Contains(name, filter)
}

// sortFamilies orders families by name so repeated scrapes render identically.
func sortFamilies(families []promFamily) {
	sort.Slice(families, func(i, j int) bool { return families[i].Name < families[j].Name })
	for i := range families {
		samples := families[i].Samples
		sort.SliceStable(samples, func(a, b int) bool {
			if samples[a].Name != samples[b].Name {
				return samples[a].Name < samples[b].Name
			}
			return samples[a].LabelString() < samples[b].LabelString()
		})
	}
}

// formatMetricValue renders a sample value compactly: integers without a
// fractional part, everything else with enough precision to be useful.
func formatMetricValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return strconv.FormatFloat(v, 'g', 6, 64)
	}
}
