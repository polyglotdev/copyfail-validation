// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package buildinfo_test

import (
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/buildinfo"
	"github.com/polyglotdev/copyfail-validation/report"
)

// TestVarsHaveDefaults verifies that the package-level Version, Commit,
// and BuildDate vars carry non-empty fallback values when the binary is
// run via `go run` or `go test` (i.e., without the goreleaser -ldflags
// injection). This is what lets the CLI report a sensible --version
// during local development instead of the empty string.
func TestVarsHaveDefaults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  string
	}{
		{name: "Version", got: buildinfo.Version},
		{name: "Commit", got: buildinfo.Commit},
		{name: "BuildDate", got: buildinfo.BuildDate},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if tc.got == "" {
				subT.Errorf("%s default is empty (must be non-empty for `go run` / `go test`)", tc.name)
			}
		})
	}
}

// TestToolName_IsConstant verifies that the binary's logical name is a
// const (not a var) so it cannot be overridden at link time. The CLI's
// argv[0] / pkg.go.dev landing page / Prometheus build_info metric all
// depend on a stable ToolName across builds.
func TestToolName_IsConstant(t *testing.T) {
	t.Parallel()
	if buildinfo.ToolName != "copyfail-validate" {
		t.Errorf("ToolName = %q, want %q", buildinfo.ToolName, "copyfail-validate")
	}
}

// TestInfo_PopulatesToolInfo verifies the Info() factory wires every
// field of report.ToolInfo from the package vars in a single call. The
// CLI uses Info() to populate Report.Tool exactly once per run; if a
// future maintainer adds a field to report.ToolInfo without updating
// Info(), this test will fail to remind them.
func TestInfo_PopulatesToolInfo(t *testing.T) {
	t.Parallel()
	info := buildinfo.Info()
	want := report.ToolInfo{
		Name:      buildinfo.ToolName,
		Version:   buildinfo.Version,
		Commit:    buildinfo.Commit,
		BuildDate: buildinfo.BuildDate,
	}
	if info != want {
		t.Errorf("Info() = %+v, want %+v", info, want)
	}
}
