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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/obsernetics/pahlevan/pkg/coverage"
)

func TestCoverageCommand_Table(t *testing.T) {
	cmd := NewCoverageCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})

	require.NoError(t, cmd.Execute())

	got := out.String()
	assert.Contains(t, got, "DETECTOR")
	assert.Contains(t, got, "HOOK")
	assert.Contains(t, got, "NEEDS LSM")
	for _, d := range []string{"file", "network", "exec", "capability", "syscall", "cred", "shell"} {
		assert.Contains(t, got, d)
	}
	assert.Contains(t, got, "technique(s) across 7 detector(s)")
}

func TestCoverageCommand_JSON(t *testing.T) {
	cmd := NewCoverageCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"-o", "json"})

	require.NoError(t, cmd.Execute())

	assert.Contains(t, out.String(), `"Detector": "file"`)
	assert.Contains(t, out.String(), "T1059.004")
}

func TestCoverageCommand_YAML(t *testing.T) {
	cmd := NewCoverageCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"-o", "yaml"})

	require.NoError(t, cmd.Execute())

	assert.Contains(t, out.String(), "Detector: file")
}

func TestCoverageCommand_IsOffline(t *testing.T) {
	cmd := NewCoverageCommand()
	assert.True(t, IsOffline(cmd), "coverage reads only the compiled-in table and must not require a cluster")
}

func TestRunCoverage_UnknownFormatIsRejected(t *testing.T) {
	cmd := NewCoverageCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := runCoverage(cmd, "nonsense")
	require.Error(t, err, "an unrecognized --output must fail fast rather than produce empty or wrong output")
	assert.Contains(t, err.Error(), "nonsense")
}

func TestRunCoverage_TableIncludesEveryTechniqueID(t *testing.T) {
	cmd := NewCoverageCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, runCoverage(cmd, "table"))

	got := out.String()
	for _, tech := range coverage.Techniques() {
		assert.Contains(t, got, tech.ID)
	}
}
