// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

import "time"

// SchemaVersionCurrent is the schema version emitted by Report values
// constructed in this build. Bumping this is a major change per
// docs/schema.md.
const SchemaVersionCurrent = "1.0.0"

// Report is the canonical aggregate of a single validator run.
//
// Field declaration order favors compact GC scan ranges (govet
// fieldalignment); the JSON wire format is driven by the struct tags
// below and is independent of declaration order.
type Report struct {
	Generated     time.Time `json:"generated_at"`
	Host          HostInfo  `json:"host"`
	Tool          ToolInfo  `json:"tool"`
	SchemaVersion string    `json:"schema_version"`
	Results       []Result  `json:"results"`
	Summary       Summary   `json:"summary"`
}

// ToolInfo describes the build that produced a Report.
type ToolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

// HostInfo describes the host the validator ran against.
type HostInfo struct {
	Hostname      string `json:"hostname"`
	KernelRelease string `json:"kernel_release"`
	OSRelease     string `json:"os_release"`
	OSVersion     string `json:"os_version_id"`
	Arch          string `json:"arch"`
}

// Summary is a tally of Result states across one Report. The Required
// breakdown drives the process exit code (see cmd/copyfail-validate/exit.go
// and the spec §6).
type Summary struct {
	Total    int    `json:"total"`
	Pass     int    `json:"pass"`
	Fail     int    `json:"fail"`
	Skip     int    `json:"skip"`
	Error    int    `json:"error"`
	Required Bucket `json:"required"`
}

// Bucket is the per-severity tally used inside Summary.Required.
// Error is included so callers can compute the exit code without
// re-iterating Results (spec §4 / §6).
type Bucket struct {
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Error int `json:"error"`
}

// NewSummary computes a Summary from a Results slice. Pure function; the
// input slice is not modified.
func NewSummary(results []Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.State {
		case StatePass:
			s.Pass++
		case StateFail:
			s.Fail++
		case StateSkip:
			s.Skip++
		case StateError:
			s.Error++
		}
		if r.Severity.IsRequired() {
			switch r.State {
			case StatePass:
				s.Required.Pass++
			case StateFail:
				s.Required.Fail++
			case StateError:
				s.Required.Error++
			}
			// Required Skip is intentionally NOT tracked separately —
			// a required Skip counts in s.Skip but does not affect the
			// exit code (spec §6: only Required.Fail and Required.Error do).
		}
	}
	return s
}
