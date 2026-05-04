// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/render"
	"github.com/polyglotdev/copyfail-validation/report"
)

// TestRender_SARIF_Golden pins the SARIF renderer's pretty-printed
// output against testdata/golden/sarif/basic.sarif. Run with -update
// to regenerate the fixture.
func TestRender_SARIF_Golden(t *testing.T) {
	t.Parallel()
	rep := fixedReport()
	var buf bytes.Buffer
	n, err := render.RenderSARIF(&buf, rep)
	if err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Errorf("RenderSARIF returned n=%d but wrote %d bytes", n, buf.Len())
	}

	goldenPath := filepath.Join("testdata", "golden", "sarif", "basic.sarif")
	if *updateGolden {
		writeGolden(t, goldenPath, buf.Bytes())
	}
	want := readGolden(t, goldenPath)
	if diff := cmp.Diff(string(want), buf.String()); diff != "" {
		t.Errorf("RenderSARIF golden mismatch (-want +got):\n%s\n(rerun with -update to refresh)", diff)
	}
}

// TestRender_SARIF_ValidJSON verifies the rendered bytes decode
// cleanly into a map[string]any. This is the cheapest "is it
// well-formed?" assertion we can make without pulling in a
// JSON-schema validator (forbidden by the v0.1 stdlib-only contract).
func TestRender_SARIF_ValidJSON(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if _, err := render.RenderSARIF(&buf, fixedReport()); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("json.Unmarshal: %v\npayload:\n%s", err, buf.String())
	}
	for _, key := range []string{"$schema", "version", "runs"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("rendered SARIF missing required top-level key %q", key)
		}
	}
	if v, ok := doc["version"].(string); !ok || v != "2.1.0" {
		t.Errorf("version = %v, want %q", doc["version"], "2.1.0")
	}
}

// TestRender_SARIF_KindMappingPerResult verifies result.kind for
// each Result matches State.SARIFKind() and that the index alignment
// is preserved (i.e., results[i] in the SARIF output corresponds to
// rep.Results[i] in the input).
func TestRender_SARIF_KindMappingPerResult(t *testing.T) {
	t.Parallel()
	rep := fixedReport()
	var buf bytes.Buffer
	if _, err := render.RenderSARIF(&buf, rep); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}

	doc := mustUnmarshalSARIF(t, buf.Bytes())
	gotResults := mustGetResults(t, doc)
	if len(gotResults) != len(rep.Results) {
		t.Fatalf("results length: got=%d want=%d", len(gotResults), len(rep.Results))
	}

	for i, want := range rep.Results {
		got := gotResults[i].(map[string]any)
		gotKind, _ := got["kind"].(string)
		if gotKind != want.State.SARIFKind() {
			t.Errorf("result[%d] kind: got=%q want=%q", i, gotKind, want.State.SARIFKind())
		}
		gotRule, _ := got["ruleId"].(string)
		if gotRule != want.CheckID {
			t.Errorf("result[%d] ruleId: got=%q want=%q", i, gotRule, want.CheckID)
		}
	}
}

// TestRender_SARIF_LevelForFailures verifies level = "error" for a
// failed required check, "warning" for a failed advisory check, and
// is absent (defaulted to none by SARIF) otherwise.
func TestRender_SARIF_LevelForFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		wantLevel string // empty string means the key must be absent
		result    report.Result
	}{
		{
			name:      "required fail is error",
			result:    report.Result{CheckID: "x", State: report.StateFail, Severity: report.SeverityRequired},
			wantLevel: "error",
		},
		{
			name:      "advisory fail is warning",
			result:    report.Result{CheckID: "x", State: report.StateFail, Severity: report.SeverityAdvisory},
			wantLevel: "warning",
		},
		{
			name:      "pass has no level",
			result:    report.Result{CheckID: "x", State: report.StatePass, Severity: report.SeverityRequired},
			wantLevel: "",
		},
		{
			name:      "skip has no level",
			result:    report.Result{CheckID: "x", State: report.StateSkip, Severity: report.SeverityAdvisory},
			wantLevel: "",
		},
		{
			name:      "error has no level",
			result:    report.Result{CheckID: "x", State: report.StateError, Severity: report.SeverityRequired, Err: "boom"},
			wantLevel: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			rep := report.Report{Results: []report.Result{tc.result}, Summary: report.NewSummary([]report.Result{tc.result})}
			var buf bytes.Buffer
			if _, err := render.RenderSARIF(&buf, rep); err != nil {
				subT.Fatalf("RenderSARIF: %v", err)
			}
			doc := mustUnmarshalSARIF(subT, buf.Bytes())
			got := mustGetResults(subT, doc)[0].(map[string]any)
			level, present := got["level"]
			if tc.wantLevel == "" {
				if present {
					subT.Errorf("level present (%v); want absent for state=%s severity=%s",
						level, tc.result.State, tc.result.Severity)
				}
				return
			}
			if !present {
				subT.Errorf("level absent; want %q", tc.wantLevel)
				return
			}
			if got := level.(string); got != tc.wantLevel {
				subT.Errorf("level = %q, want %q", got, tc.wantLevel)
			}
		})
	}
}

// TestRender_SARIF_RulesAreDeduplicated verifies that a Report
// containing two Results from the same CheckID produces exactly one
// rule descriptor in the driver. This matches the SARIF spec —
// rule.id is the unique key inside a driver.
func TestRender_SARIF_RulesAreDeduplicated(t *testing.T) {
	t.Parallel()
	rep := report.Report{
		SchemaVersion: report.SchemaVersionCurrent,
		Generated:     mustParseRFC3339("2026-05-04T12:00:00Z"),
		Tool:          report.ToolInfo{Name: "copyfail-validate", Version: "v0.1.0"},
		Results: []report.Result{
			{CheckID: "x", Title: "X", State: report.StatePass, Severity: report.SeverityRequired},
			{CheckID: "x", Title: "X (retry)", State: report.StateFail, Severity: report.SeverityRequired},
			{CheckID: "y", Title: "Y", State: report.StatePass, Severity: report.SeverityAdvisory},
		},
	}
	rep.Summary = report.NewSummary(rep.Results)

	var buf bytes.Buffer
	if _, err := render.RenderSARIF(&buf, rep); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	doc := mustUnmarshalSARIF(t, buf.Bytes())
	rules := mustGetRules(t, doc)
	if got := len(rules); got != 2 {
		t.Errorf("rules: got=%d want=2 (deduplicated by CheckID)", got)
	}
	gotIDs := map[string]bool{}
	for _, r := range rules {
		id, _ := r.(map[string]any)["id"].(string)
		gotIDs[id] = true
	}
	for _, want := range []string{"x", "y"} {
		if !gotIDs[want] {
			t.Errorf("rules missing id %q", want)
		}
	}
}

// TestRender_SARIF_ExecutionSuccessful verifies the invocation flag
// follows the spec §6 exit-code contract.
func TestRender_SARIF_ExecutionSuccessful(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		results []report.Result
		want    bool
	}{
		{
			name: "all pass is successful",
			results: []report.Result{
				{CheckID: "a", State: report.StatePass, Severity: report.SeverityRequired},
			},
			want: true,
		},
		{
			name: "advisory fail is still successful",
			results: []report.Result{
				{CheckID: "a", State: report.StateFail, Severity: report.SeverityAdvisory},
			},
			want: true,
		},
		{
			name: "required fail is unsuccessful",
			results: []report.Result{
				{CheckID: "a", State: report.StateFail, Severity: report.SeverityRequired},
			},
			want: false,
		},
		{
			name: "required error is unsuccessful",
			results: []report.Result{
				{CheckID: "a", State: report.StateError, Severity: report.SeverityRequired, Err: "boom"},
			},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			rep := report.Report{Results: tc.results, Summary: report.NewSummary(tc.results)}
			var buf bytes.Buffer
			if _, err := render.RenderSARIF(&buf, rep); err != nil {
				subT.Fatalf("RenderSARIF: %v", err)
			}
			doc := mustUnmarshalSARIF(subT, buf.Bytes())
			runs := doc["runs"].([]any)
			run := runs[0].(map[string]any)
			invs := run["invocations"].([]any)
			inv := invs[0].(map[string]any)
			got := inv["executionSuccessful"].(bool)
			if got != tc.want {
				subT.Errorf("executionSuccessful: got=%v want=%v", got, tc.want)
			}
		})
	}
}

// TestRender_SARIF_WriterError verifies a writer that fails on
// Write surfaces a wrapped ErrRender.
func TestRender_SARIF_WriterError(t *testing.T) {
	t.Parallel()
	w := &errWriter{err: errors.New("disk full")}
	_, err := render.RenderSARIF(w, fixedReport())
	if err == nil {
		t.Fatal("RenderSARIF: nil error on writer failure")
	}
	if !errors.Is(err, render.ErrRender) {
		t.Errorf("err not wrapped with ErrRender: %v", err)
	}
}

// mustUnmarshalSARIF unmarshals SARIF bytes into a generic map and
// fails the test on error.
func mustUnmarshalSARIF(t testing.TB, b []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal SARIF: %v\npayload:\n%s", err, string(b))
	}
	return doc
}

// mustGetResults returns runs[0].results from a decoded SARIF
// document, failing the test if any cast fails.
func mustGetResults(t testing.TB, doc map[string]any) []any {
	t.Helper()
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatalf("runs missing or empty")
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("runs[0] not an object")
	}
	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf("runs[0].results not an array")
	}
	return results
}

// mustGetRules returns runs[0].tool.driver.rules from a decoded
// SARIF document, failing the test if any cast fails.
func mustGetRules(t testing.TB, doc map[string]any) []any {
	t.Helper()
	runs := doc["runs"].([]any)
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules, ok := driver["rules"].([]any)
	if !ok {
		t.Fatalf("rules not an array")
	}
	return rules
}
