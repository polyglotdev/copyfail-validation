// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/report"
)

// TestNewSummary pins the contract that drives the process exit code in
// cmd/copyfail-validate (spec §6). The Required bucket counts only
// required-severity Pass/Fail/Error — required Skip is intentionally
// NOT bucketed because the exit-code computation only branches on
// Required.Fail and Required.Error. Advisory results affect the totals
// but never the Required bucket. NewSummary is a pure function — the
// input slice is not mutated.
func TestNewSummary(t *testing.T) {
	t.Parallel()

	required := func(state report.State) report.Result {
		return report.Result{State: state, Severity: report.SeverityRequired}
	}
	advisory := func(state report.State) report.Result {
		return report.Result{State: state, Severity: report.SeverityAdvisory}
	}

	tests := []struct {
		name    string
		results []report.Result
		want    report.Summary
	}{
		{
			name:    "empty slice produces zero summary",
			results: nil,
			want:    report.Summary{},
		},
		{
			name: "mixed states across required and advisory",
			results: []report.Result{
				required(report.StatePass),
				required(report.StateFail),
				required(report.StateError),
				advisory(report.StateSkip),
				advisory(report.StatePass),
			},
			want: report.Summary{
				Total:    5,
				Pass:     2,
				Fail:     1,
				Skip:     1,
				Error:    1,
				Required: report.Bucket{Pass: 1, Fail: 1, Error: 1},
			},
		},
		{
			name: "advisory failures do not populate required bucket",
			results: []report.Result{
				advisory(report.StateFail),
				advisory(report.StateError),
				advisory(report.StateFail),
			},
			want: report.Summary{
				Total: 3,
				Fail:  2,
				Error: 1,
			},
		},
		{
			name: "required skip counts in Skip total but not in required bucket (spec §6)",
			results: []report.Result{
				required(report.StateSkip),
				required(report.StatePass),
			},
			want: report.Summary{
				Total:    2,
				Pass:     1,
				Skip:     1,
				Required: report.Bucket{Pass: 1},
			},
		},
		{
			name: "all-pass required run is exit-code-clean",
			results: []report.Result{
				required(report.StatePass),
				required(report.StatePass),
				advisory(report.StatePass),
			},
			want: report.Summary{
				Total:    3,
				Pass:     3,
				Required: report.Bucket{Pass: 2},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			got := report.NewSummary(tc.results)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				subT.Errorf("NewSummary mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestReport_JSONIncludesSchemaVersion guards the schema-version field
// against being silently dropped from serialized output. Downstream
// JSON consumers branch on Report.SchemaVersion to decide which parser
// version to use; if it ever became `omitempty` and a default-value
// Report were emitted, those consumers would silently misroute.
func TestReport_JSONIncludesSchemaVersion(t *testing.T) {
	t.Parallel()
	rep := report.Report{
		SchemaVersion: report.SchemaVersionCurrent,
		Tool:          report.ToolInfo{Name: "copyfail-validate", Version: "v0.0.0-test"},
		Host:          report.HostInfo{Hostname: "test-host"},
		Generated:     time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if uerr := json.Unmarshal(b, &m); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}

	got, ok := m["schema_version"].(string)
	if !ok {
		t.Fatalf("schema_version is not a string: %T (%v)", m["schema_version"], m["schema_version"])
	}
	if got != report.SchemaVersionCurrent {
		t.Errorf("schema_version = %q, want %q", got, report.SchemaVersionCurrent)
	}
}
