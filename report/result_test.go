// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/report"
)

// TestResult_JSONShape verifies that a fully populated Result marshals
// to the exact JSON shape downstream consumers depend on (SSM aggregators,
// jq pipelines, SARIF converters, Lambda parsers). The expected map is
// the CONTRACT — any change to it requires a Report.SchemaVersion bump.
//
// Struct field order is independent of JSON key order: the encoder
// honors json: tag declaration order, so the fieldalignment-driven
// struct layout cannot regress this test.
func TestResult_JSONShape(t *testing.T) {
	t.Parallel()
	startedAt, perr := time.Parse(time.RFC3339, "2026-05-04T12:34:56Z")
	if perr != nil {
		t.Fatalf("parse fixture timestamp: %v", perr)
	}

	r := report.Result{
		CheckID:    "modprobe.dry_run",
		Title:      "Modprobe dry-run resolves to /bin/false",
		State:      report.StatePass,
		Severity:   report.SeverityRequired,
		StartedAt:  startedAt,
		DurationMS: 18,
		Detail:     "ok",
		Evidence: map[string]any{
			"command":   "modprobe -n -v algif_aead",
			"exit_code": float64(0),
		},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if uerr := json.Unmarshal(b, &got); uerr != nil {
		t.Fatalf("unmarshal: %v", uerr)
	}
	want := map[string]any{
		"check_id":    "modprobe.dry_run",
		"title":       "Modprobe dry-run resolves to /bin/false",
		"state":       "pass",
		"severity":    "required",
		"started_at":  "2026-05-04T12:34:56Z",
		"duration_ms": float64(18),
		"detail":      "ok",
		"evidence": map[string]any{
			"command":   "modprobe -n -v algif_aead",
			"exit_code": float64(0),
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Result JSON mismatch (-want +got):\n%s", diff)
	}
}

// TestResult_OmitsEmptyOptionalFields verifies the omitempty behavior for
// the three optional fields (Detail, Evidence, Err). Each table case
// asserts both presence (mustHave) and absence (mustNotHave) of expected
// JSON keys — a stricter form than `strings.Contains(s, "...")` because
// the substring assertions are scoped to literal `"key":...` patterns
// that cannot accidentally match data values.
func TestResult_OmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		result      report.Result
		name        string
		mustNotHave []string
		mustHave    []string
	}{
		{
			name: "advisory pass with no detail/evidence/error",
			result: report.Result{
				CheckID:  "x",
				Title:    "y",
				State:    report.StatePass,
				Severity: report.SeverityAdvisory,
			},
			mustNotHave: []string{`"detail"`, `"evidence"`, `"error"`},
			mustHave:    []string{`"check_id":"x"`, `"state":"pass"`, `"severity":"advisory"`},
		},
		{
			name: "error result keeps error field, omits detail and evidence",
			result: report.Result{
				CheckID:  "x",
				Title:    "y",
				State:    report.StateError,
				Severity: report.SeverityRequired,
				Err:      "boom",
			},
			mustNotHave: []string{`"detail"`, `"evidence"`},
			mustHave:    []string{`"error":"boom"`, `"state":"error"`},
		},
		{
			name: "non-empty evidence is retained",
			result: report.Result{
				CheckID:  "x",
				Title:    "y",
				State:    report.StatePass,
				Severity: report.SeverityAdvisory,
				Evidence: map[string]any{"k": "v"},
			},
			mustNotHave: []string{`"detail"`, `"error"`},
			mustHave:    []string{`"evidence":{"k":"v"}`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			b, err := json.Marshal(tc.result)
			if err != nil {
				subT.Fatalf("marshal: %v", err)
			}
			s := string(b)
			for _, key := range tc.mustNotHave {
				if strings.Contains(s, key) {
					subT.Errorf("expected %s to be omitted from %s", key, s)
				}
			}
			for _, key := range tc.mustHave {
				if !strings.Contains(s, key) {
					subT.Errorf("expected %s to appear in %s", key, s)
				}
			}
		})
	}
}
