// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package buildinfo holds build-time-injected version metadata. The
// Version, Commit, and BuildDate vars are overridden at link time via
// -ldflags="-X github.com/polyglotdev/copyfail-validation/internal/buildinfo.Version=...".
// Defaults exist so `go run` and `go test` produce non-empty values.
package buildinfo

import "github.com/polyglotdev/copyfail-validation/report"

// ToolName is the canonical binary name. Not overridable.
const ToolName = "copyfail-validate"

// Build-time-injected metadata. Overridden by goreleaser via -ldflags.
var (
	Version   = "v0.0.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Info returns a report.ToolInfo populated from the package vars.
func Info() report.ToolInfo {
	return report.ToolInfo{
		Name:      ToolName,
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
	}
}
