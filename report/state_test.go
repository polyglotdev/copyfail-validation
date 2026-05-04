// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"encoding/json"
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

// TestState_Constants pins the wire string for every public State value.
// These strings are part of the JSON schema contract (spec §5) and the
// SARIF rule mapping; renaming or rotating one is a major version bump.
func TestState_Constants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  report.State
		want string
	}{
		{name: "pass", got: report.StatePass, want: "pass"},
		{name: "fail", got: report.StateFail, want: "fail"},
		{name: "skip", got: report.StateSkip, want: "skip"},
		{name: "error", got: report.StateError, want: "error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if string(tc.got) != tc.want {
				subT.Errorf("State string = %q, want %q", string(tc.got), tc.want)
			}
		})
	}
}

// TestState_JSONRoundtrip verifies that every State value survives a
// json.Marshal → json.Unmarshal round trip unchanged. This guards against
// a future maintainer adding a State value but forgetting to extend the
// implicit string contract used by the JSON encoder.
func TestState_JSONRoundtrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		state report.State
	}{
		{name: "pass", state: report.StatePass},
		{name: "fail", state: report.StateFail},
		{name: "skip", state: report.StateSkip},
		{name: "error", state: report.StateError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			b, err := json.Marshal(tc.state)
			if err != nil {
				subT.Fatalf("marshal: %v", err)
			}
			var got report.State
			if uerr := json.Unmarshal(b, &got); uerr != nil {
				subT.Fatalf("unmarshal: %v", uerr)
			}
			if got != tc.state {
				subT.Errorf("roundtrip: got %q, want %q", got, tc.state)
			}
		})
	}
}

// TestState_SARIFKind verifies the State → SARIF v2.1.0 result.kind
// mapping documented on the State type. Critically, unknown / empty
// states fail-safe to "open" (per the godoc) so unexpected values never
// silently report as a "pass" downstream.
func TestState_SARIFKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		state report.State
		want  string
	}{
		{name: "pass maps to pass", state: report.StatePass, want: "pass"},
		{name: "fail maps to fail", state: report.StateFail, want: "fail"},
		{name: "skip maps to notApplicable", state: report.StateSkip, want: "notApplicable"},
		{name: "error maps to open", state: report.StateError, want: "open"},
		{name: "unknown state fails safe to open", state: report.State("legacy"), want: "open"},
		{name: "empty state fails safe to open", state: report.State(""), want: "open"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if got := tc.state.SARIFKind(); got != tc.want {
				subT.Errorf("State(%q).SARIFKind() = %q, want %q", tc.state, got, tc.want)
			}
		})
	}
}
