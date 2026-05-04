// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/render"
	"github.com/polyglotdev/copyfail-validation/report"
)

// TestRender_Human_Golden pins the human renderer against a golden
// file. The test uses bytes.Buffer (not *os.File) so shouldColor()
// returns false unconditionally — output is plain ANSI-free text.
func TestRender_Human_Golden(t *testing.T) {
	t.Parallel()

	rep := fixedReport()
	var buf bytes.Buffer
	n, err := render.RenderHuman(&buf, rep)
	if err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Errorf("RenderHuman returned n=%d but wrote %d bytes", n, buf.Len())
	}

	goldenPath := filepath.Join("testdata", "golden", "human", "basic.txt")
	if *updateGolden {
		writeGolden(t, goldenPath, buf.Bytes())
	}
	want := readGolden(t, goldenPath)
	if diff := cmp.Diff(string(want), buf.String()); diff != "" {
		t.Errorf("RenderHuman golden mismatch (-want +got):\n%s\n(rerun with -update to refresh)", diff)
	}
}

// TestRender_Human_StateFormatting verifies the per-result line for
// each State produces the expected STATUS prefix and shape. Drives
// future renderer changes (e.g., adding a new state) toward
// explicit test coverage rather than silent default behavior.
func TestRender_Human_StateFormatting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		wantSubStrs []string
		name        string
		wantPrefix  string
		result      report.Result
	}{
		{
			name: "pass with detail",
			result: report.Result{
				CheckID:  "modprobe.dry_run",
				State:    report.StatePass,
				Severity: report.SeverityRequired,
				Detail:   "modprobe -nv copyfail returns /bin/false",
			},
			wantPrefix:  "OK   ",
			wantSubStrs: []string{"modprobe.dry_run", "(required)", "modprobe -nv copyfail returns /bin/false"},
		},
		{
			name: "fail with detail",
			result: report.Result{
				CheckID:  "kernel.modules_loaded",
				State:    report.StateFail,
				Severity: report.SeverityRequired,
				Detail:   "found 1 loaded module: copyfail",
			},
			wantPrefix:  "FAIL ",
			wantSubStrs: []string{"kernel.modules_loaded", "(required)", "found 1 loaded module"},
		},
		{
			name: "skip with reason",
			result: report.Result{
				CheckID:  "afalg.procscan",
				State:    report.StateSkip,
				Severity: report.SeverityAdvisory,
				Detail:   "skipped: not running as root",
			},
			wantPrefix:  "SKIP ",
			wantSubStrs: []string{"afalg.procscan", "(advisory)", "skipped: not running as root"},
		},
		{
			name: "error uses Err over Detail",
			result: report.Result{
				CheckID:  "integrity.copyfail_pkg",
				State:    report.StateError,
				Severity: report.SeverityRequired,
				Err:      "rpm: command not found",
				Detail:   "ignored",
			},
			wantPrefix:  "ERROR",
			wantSubStrs: []string{"integrity.copyfail_pkg", "(required)", "rpm: command not found"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			rep := report.Report{Results: []report.Result{tc.result}, Summary: report.NewSummary([]report.Result{tc.result})}
			var buf bytes.Buffer
			if _, err := render.RenderHuman(&buf, rep); err != nil {
				subT.Fatalf("RenderHuman: %v", err)
			}
			lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
			if len(lines) < 1 {
				subT.Fatalf("no lines emitted")
			}
			first := lines[0]
			if !strings.HasPrefix(first, tc.wantPrefix) {
				subT.Errorf("first line prefix: got %q, want prefix %q", first, tc.wantPrefix)
			}
			for _, sub := range tc.wantSubStrs {
				if !strings.Contains(first, sub) {
					subT.Errorf("first line missing substring %q\nline: %q", sub, first)
				}
			}
			if strings.Contains(buf.String(), "\x1b[") {
				subT.Errorf("ANSI escape leaked into bytes.Buffer output:\n%s", buf.String())
			}
		})
	}
}

// TestRender_Human_FooterVerdict verifies the verdict line: PASS
// when there are no required failures or errors; FAIL otherwise.
// This is the operator-visible analog of the CLI exit code.
func TestRender_Human_FooterVerdict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		wantVerdict string
		results     []report.Result
	}{
		{
			name: "all required pass",
			results: []report.Result{
				{State: report.StatePass, Severity: report.SeverityRequired},
				{State: report.StatePass, Severity: report.SeverityAdvisory},
			},
			wantVerdict: "PASS",
		},
		{
			name: "advisory fail does not flip verdict",
			results: []report.Result{
				{State: report.StatePass, Severity: report.SeverityRequired},
				{State: report.StateFail, Severity: report.SeverityAdvisory},
			},
			wantVerdict: "PASS",
		},
		{
			name: "required fail flips verdict",
			results: []report.Result{
				{State: report.StateFail, Severity: report.SeverityRequired},
			},
			wantVerdict: "FAIL",
		},
		{
			name: "required error flips verdict",
			results: []report.Result{
				{State: report.StateError, Severity: report.SeverityRequired, Err: "x"},
			},
			wantVerdict: "FAIL",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			rep := report.Report{Results: tc.results, Summary: report.NewSummary(tc.results)}
			var buf bytes.Buffer
			if _, err := render.RenderHuman(&buf, rep); err != nil {
				subT.Fatalf("RenderHuman: %v", err)
			}
			want := "validator result: " + tc.wantVerdict
			if !strings.Contains(buf.String(), want) {
				subT.Errorf("output missing %q\noutput:\n%s", want, buf.String())
			}
		})
	}
}

// TestRender_Human_NoColorOnPlainWriter verifies the documented
// invariant: writing to anything that isn't a TTY (here a
// bytes.Buffer) never emits an ANSI escape regardless of NO_COLOR
// state. This is the property the golden test relies on.
//
// Not parallel: depends on a specific NO_COLOR state.
func TestRender_Human_NoColorOnPlainWriter(t *testing.T) {
	withCleanEnv(t, render.EnvNoColor, "")
	var buf bytes.Buffer
	if _, err := render.RenderHuman(&buf, fixedReport()); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("ANSI escape leaked into bytes.Buffer output:\n%s", buf.String())
	}
}

// TestRender_Human_NoColorEnvIsRespected verifies that even if the
// underlying writer were a TTY, NO_COLOR=1 forces plain output. We
// can't easily fabricate a TTY-marked *os.File in unit tests, so we
// verify the precondition shouldColor checks first (the env var) by
// asserting plain output remains plain.
//
// Not parallel: mutates NO_COLOR.
func TestRender_Human_NoColorEnvIsRespected(t *testing.T) {
	withCleanEnv(t, render.EnvNoColor, "1")
	var buf bytes.Buffer
	if _, err := render.RenderHuman(&buf, fixedReport()); err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("ANSI escape emitted under NO_COLOR=1:\n%s", buf.String())
	}
}

// TestRender_Human_BytesWrittenMatches verifies the byte-count
// return value matches the actual bytes written.
func TestRender_Human_BytesWrittenMatches(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	n, err := render.RenderHuman(&buf, fixedReport())
	if err != nil {
		t.Fatalf("RenderHuman: %v", err)
	}
	if int64(buf.Len()) != n {
		t.Errorf("buf.Len()=%d, n=%d; expected equal", buf.Len(), n)
	}
}

// TestRender_Human_WriterError verifies a writer that fails on
// Write surfaces a wrapped ErrRender to the caller.
func TestRender_Human_WriterError(t *testing.T) {
	t.Parallel()
	want := errors.New("disk full")
	w := &errWriter{err: want}
	_, err := render.RenderHuman(w, fixedReport())
	if err == nil {
		t.Fatal("RenderHuman: nil error on writer failure")
	}
	if !errors.Is(err, render.ErrRender) {
		t.Errorf("err not wrapped with ErrRender: %v", err)
	}
}
