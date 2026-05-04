// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

// TestSeverity_Constants pins the wire string for every public Severity
// value. Required vs Advisory drives the process exit code (spec §6) and
// is part of the JSON schema contract; rotating either string is a major
// version bump.
func TestSeverity_Constants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		got  report.Severity
		name string
		want string
	}{
		{name: "required", got: report.SeverityRequired, want: "required"},
		{name: "advisory", got: report.SeverityAdvisory, want: "advisory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if string(tc.got) != tc.want {
				subT.Errorf("Severity string = %q, want %q", string(tc.got), tc.want)
			}
		})
	}
}

// TestSeverity_IsRequired verifies that IsRequired returns true ONLY for
// SeverityRequired. Unknown / empty / legacy values must return false so
// the exit-code calculator (spec §6) treats them conservatively as
// advisory rather than promoting them to required.
func TestSeverity_IsRequired(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sev  report.Severity
		want bool
	}{
		{name: "required is required", sev: report.SeverityRequired, want: true},
		{name: "advisory is not required", sev: report.SeverityAdvisory, want: false},
		{name: "unknown severity is not required", sev: report.Severity("legacy"), want: false},
		{name: "empty severity is not required", sev: report.Severity(""), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if got := tc.sev.IsRequired(); got != tc.want {
				subT.Errorf("Severity(%q).IsRequired() = %t, want %t", tc.sev, got, tc.want)
			}
		})
	}
}
