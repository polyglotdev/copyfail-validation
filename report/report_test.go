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

func TestReport_SummaryComputed(t *testing.T) {
	t.Parallel()
	rep := report.Report{
		SchemaVersion: "1.0.0",
		Tool:          report.ToolInfo{Name: "copyfail-validate", Version: "v0.0.0-test"},
		Host:          report.HostInfo{Hostname: "test-host"},
		Generated:     time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
		Results: []report.Result{
			{CheckID: "a", State: report.StatePass, Severity: report.SeverityRequired},
			{CheckID: "b", State: report.StateFail, Severity: report.SeverityRequired},
			{CheckID: "c", State: report.StateError, Severity: report.SeverityRequired},
			{CheckID: "d", State: report.StateSkip, Severity: report.SeverityAdvisory},
			{CheckID: "e", State: report.StatePass, Severity: report.SeverityAdvisory},
		},
	}
	rep.Summary = report.NewSummary(rep.Results)
	want := report.Summary{
		Total:    5,
		Pass:     2,
		Fail:     1,
		Skip:     1,
		Error:    1,
		Required: report.Bucket{Pass: 1, Fail: 1, Error: 1},
	}
	if diff := cmp.Diff(want, rep.Summary); diff != "" {
		t.Errorf("Summary mismatch (-want +got):\n%s", diff)
	}
	// Sanity: scaffolding fields on the constructed Report are retained
	// (also satisfies govet unusedwrite for the SchemaVersion/Generated
	// fields set above).
	if rep.SchemaVersion == "" || rep.Generated.IsZero() {
		t.Errorf("scaffolding fields not retained: SchemaVersion=%q Generated=%v", rep.SchemaVersion, rep.Generated)
	}
}

func TestReport_JSONIncludesSchemaVersion(t *testing.T) {
	t.Parallel()
	rep := report.Report{SchemaVersion: "1.0.0"}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, ok := m["schema_version"].(string); !ok || got != "1.0.0" {
		t.Errorf("schema_version = %v, want \"1.0.0\"", m["schema_version"])
	}
}
