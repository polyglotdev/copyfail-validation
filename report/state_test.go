// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"encoding/json"
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

func TestState_Constants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  report.State
		want string
	}{
		{"pass", report.StatePass, "pass"},
		{"fail", report.StateFail, "fail"},
		{"skip", report.StateSkip, "skip"},
		{"error", report.StateError, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if string(tt.got) != tt.want {
				t.Errorf("State(%q) = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestState_JSONRoundtrip(t *testing.T) {
	t.Parallel()
	for _, s := range []report.State{report.StatePass, report.StateFail, report.StateSkip, report.StateError} {
		s := s
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got report.State
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got != s {
				t.Errorf("roundtrip: got %q, want %q", got, s)
			}
		})
	}
}

func TestState_SARIFKind(t *testing.T) {
	t.Parallel()
	tests := map[report.State]string{
		report.StatePass:  "pass",
		report.StateFail:  "fail",
		report.StateSkip:  "notApplicable",
		report.StateError: "open",
	}
	for s, want := range tests {
		s, want := s, want
		t.Run(string(s), func(t *testing.T) {
			t.Parallel()
			if got := s.SARIFKind(); got != want {
				t.Errorf("State(%q).SARIFKind() = %q, want %q", s, got, want)
			}
		})
	}
}
