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

func TestResult_JSONShape(t *testing.T) {
	t.Parallel()
	startedAt, _ := time.Parse(time.RFC3339, "2026-05-04T12:34:56Z")
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
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
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

func TestResult_OmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()
	r := report.Result{
		CheckID:  "x",
		Title:    "y",
		State:    report.StatePass,
		Severity: report.SeverityAdvisory,
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, key := range []string{`"detail"`, `"evidence"`, `"error"`} {
		if strings.Contains(s, key) {
			t.Errorf("expected %s to be omitted from %s", key, s)
		}
	}
}
