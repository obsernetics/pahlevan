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
	"strings"
	"testing"
)

func TestColorizeStatus_NoColor(t *testing.T) {
	// With color disabled the result must be a plain "icon status" string with
	// no ANSI escape codes.
	got := colorizeStatus("Ready", false)
	want := StatusIcon("Ready") + " Ready"
	if got != want {
		t.Fatalf("colorizeStatus(disabled) = %q, want %q", got, want)
	}
	if strings.Contains(got, "\033[") {
		t.Fatalf("colorizeStatus(disabled) must not contain ANSI codes, got %q", got)
	}
}

func TestColorizeStatus_WithColor(t *testing.T) {
	got := colorizeStatus("Ready", true)
	if !strings.HasPrefix(got, ansiGreen) {
		t.Fatalf("colorizeStatus(enabled) for Ready should start with green, got %q", got)
	}
	if !strings.HasSuffix(got, ansiReset) {
		t.Fatalf("colorizeStatus(enabled) should end with reset, got %q", got)
	}
	if !strings.Contains(got, "Ready") {
		t.Fatalf("colorizeStatus(enabled) should contain the label, got %q", got)
	}
}

func TestColorizeStatus_UnknownColorFallsBackToPlain(t *testing.T) {
	// A status with no dedicated color must not be wrapped in escape codes,
	// even when color is enabled.
	got := colorizeStatus("SomethingCustom", true)
	if strings.Contains(got, "\033[") {
		t.Fatalf("colorizeStatus for uncolored status should be plain, got %q", got)
	}
}

func TestColorFor(t *testing.T) {
	cases := map[string]string{
		"Ready":         ansiGreen,
		"enforcing":     ansiGreen,
		"Failed":        ansiRed,
		"not ready":     ansiRed,
		"Learning":      ansiCyan,
		"warning":       ansiYellow,
		"unknown":       ansiGray,
		"":              ansiGray,
		"totallycustom": "",
	}
	for status, want := range cases {
		if got := colorFor(status); got != want {
			t.Errorf("colorFor(%q) = %q, want %q", status, got, want)
		}
	}
}

func TestColorEnabled_RespectsNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if colorEnabled() {
		t.Fatalf("colorEnabled() must be false when NO_COLOR is set")
	}
}

func TestColorizeStatus_HonorsNoColorEnv(t *testing.T) {
	// Even without a tty, NO_COLOR guarantees plain output via the public API.
	t.Setenv("NO_COLOR", "1")
	got := ColorizeStatus("Failed")
	if strings.Contains(got, "\033[") {
		t.Fatalf("ColorizeStatus with NO_COLOR must be plain, got %q", got)
	}
	if got != StatusIcon("Failed")+" Failed" {
		t.Fatalf("ColorizeStatus with NO_COLOR = %q, want plain icon+label", got)
	}
}
