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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

// OutputFormat represents the output format type
type OutputFormat string

const (
	OutputFormatTable OutputFormat = "table"
	OutputFormatJSON  OutputFormat = "json"
	OutputFormatYAML  OutputFormat = "yaml"
	OutputFormatWide  OutputFormat = "wide"
)

// OutputWriter provides utilities for formatting and writing output
type OutputWriter struct {
	Writer io.Writer
	Format OutputFormat
}

// NewOutputWriter creates a new output writer
func NewOutputWriter(format string) *OutputWriter {
	return &OutputWriter{
		Writer: os.Stdout,
		Format: OutputFormat(format),
	}
}

// WriteObject writes a single object in the specified format
func (w *OutputWriter) WriteObject(obj interface{}) error {
	switch w.Format {
	case OutputFormatJSON:
		return w.writeJSON(obj)
	case OutputFormatYAML:
		return w.writeYAML(obj)
	default:
		return fmt.Errorf("unsupported format for single object: %s", w.Format)
	}
}

// WriteTable writes a table with the given headers and rows
func (w *OutputWriter) WriteTable(headers []string, rows [][]string) error {
	if w.Format != OutputFormatTable && w.Format != OutputFormatWide {
		return fmt.Errorf("table format not supported for format: %s", w.Format)
	}

	// Simple table implementation without tablewriter
	if len(headers) > 0 {
		fmt.Fprintf(w.Writer, "%s\n", strings.Join(headers, "\t"))
	}

	for _, row := range rows {
		fmt.Fprintf(w.Writer, "%s\n", strings.Join(row, "\t"))
	}

	return nil
}

// WriteList writes a list of objects
func (w *OutputWriter) WriteList(objects []interface{}) error {
	switch w.Format {
	case OutputFormatJSON:
		return w.writeJSON(objects)
	case OutputFormatYAML:
		return w.writeYAML(objects)
	default:
		return fmt.Errorf("unsupported format for list: %s", w.Format)
	}
}

// writeJSON writes objects as JSON
func (w *OutputWriter) writeJSON(obj interface{}) error {
	encoder := json.NewEncoder(w.Writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(obj)
}

// writeYAML writes objects as YAML
func (w *OutputWriter) writeYAML(obj interface{}) error {
	data, err := yaml.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = w.Writer.Write(data)
	return err
}

// PrintSuccess prints a success message
func (w *OutputWriter) PrintSuccess(message string) {
	fmt.Fprintf(w.Writer, "✓ %s\n", message)
}

// PrintError prints an error message
func (w *OutputWriter) PrintError(message string) {
	fmt.Fprintf(w.Writer, "✗ %s\n", message)
}

// PrintWarning prints a warning message
func (w *OutputWriter) PrintWarning(message string) {
	fmt.Fprintf(w.Writer, "⚠ %s\n", message)
}

// PrintInfo prints an informational message
func (w *OutputWriter) PrintInfo(message string) {
	fmt.Fprintf(w.Writer, "ℹ %s\n", message)
}

// FormatDuration formats a duration in human-readable format
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// FormatTimestamp formats a timestamp for display
func FormatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "<none>"
	}

	now := time.Now()
	if now.Sub(t) < 24*time.Hour {
		return fmt.Sprintf("%s ago", FormatDuration(now.Sub(t)))
	}

	return t.Format("2006-01-02 15:04:05")
}

// FormatBytes formats bytes in human-readable format
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatPercentage formats a float as a percentage
func FormatPercentage(value float64) string {
	return fmt.Sprintf("%.1f%%", value*100)
}

// FormatList formats a slice of strings as a comma-separated list
func FormatList(items []string) string {
	if len(items) == 0 {
		return "<none>"
	}
	if len(items) <= 3 {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s + %d more", strings.Join(items[:3], ", "), len(items)-3)
}

// TruncateString truncates a string to the specified length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// StatusIcon returns an icon based on a status string
func StatusIcon(status string) string {
	switch strings.ToLower(status) {
	case "ready", "active", "running", "healthy", "completed", "enforcing":
		return "✓"
	case "pending", "initializing", "learning", "transitioning":
		return "◐"
	case "failed", "error", "unhealthy", "blocked":
		return "✗"
	case "warning", "degraded":
		return "⚠"
	case "unknown", "":
		return "?"
	default:
		return "○"
	}
}

// ColorizeStatus adds color to status strings (simplified for this example)
func ColorizeStatus(status string) string {
	// In a real implementation, you might use a library like fatih/color
	// For simplicity, we'll just return the status with an icon
	return fmt.Sprintf("%s %s", StatusIcon(status), status)
}

// TableRow represents a row in a table
type TableRow []string

// TableData represents table data with headers and rows
type TableData struct {
	Headers []string
	Rows    []TableRow
}

// NewTableData creates a new table data structure
func NewTableData(headers ...string) *TableData {
	return &TableData{
		Headers: headers,
		Rows:    make([]TableRow, 0),
	}
}

// AddRow adds a row to the table
func (td *TableData) AddRow(values ...string) {
	td.Rows = append(td.Rows, TableRow(values))
}

// Render renders the table using the output writer
func (td *TableData) Render(writer *OutputWriter) error {
	rows := make([][]string, len(td.Rows))
	for i, row := range td.Rows {
		rows[i] = []string(row)
	}
	return writer.WriteTable(td.Headers, rows)
}
