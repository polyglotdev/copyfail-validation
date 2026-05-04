// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/render"
	"github.com/polyglotdev/copyfail-validation/report"
)

// updateGolden, when set on the command line, makes golden-file tests
// rewrite their expected files instead of failing on a diff. Wired
// into a TestMain so the same flag covers every renderer test in this
// package.
//
//	go test -run TestRender_JSON_Golden -update ./internal/render/
var updateGolden = flag.Bool("update", false, "regenerate testdata/golden/* files instead of comparing")

// TestMain wires the package-level -update flag. We don't take the
// chance to do other one-time setup here so this stays a thin entry
// point.
func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

// fixedReport returns a deterministic Report value used by every
// golden-file test in this package. No time.Now() — the timestamps
// are pinned so the rendered bytes are stable across builds, OSes,
// and authors. Includes one Result of every State so each renderer
// gets exercised across the full state matrix.
func fixedReport() report.Report {
	t := mustParseRFC3339("2026-05-04T12:00:00Z")
	results := []report.Result{
		{
			StartedAt:  t,
			CheckID:    "modprobe.dry_run",
			Title:      "modprobe dry run resolves to /bin/false",
			State:      report.StatePass,
			Severity:   report.SeverityRequired,
			Detail:     "modprobe -nv copyfail returns /bin/false",
			DurationMS: 18,
		},
		{
			StartedAt:  t,
			CheckID:    "kernel.modules_loaded",
			Title:      "no copyfail modules loaded",
			State:      report.StateFail,
			Severity:   report.SeverityRequired,
			Detail:     "found 1 loaded module: copyfail",
			DurationMS: 4,
		},
		{
			StartedAt:  t,
			CheckID:    "afalg.procscan",
			Title:      "no AF_ALG family in /proc/<pid>/maps",
			State:      report.StateSkip,
			Severity:   report.SeverityAdvisory,
			Detail:     "skipped: not running as root",
			DurationMS: 1,
		},
		{
			StartedAt:  t,
			CheckID:    "integrity.copyfail_pkg",
			Title:      "copyfail package not installed",
			State:      report.StateError,
			Severity:   report.SeverityRequired,
			Err:        "rpm: command not found",
			DurationMS: 12,
		},
	}
	return report.Report{
		SchemaVersion: report.SchemaVersionCurrent,
		Generated:     t,
		Host: report.HostInfo{
			Hostname:      "test-host",
			KernelRelease: "6.10.0",
			OSRelease:     "ubuntu",
			OSVersion:     "24.04",
			Arch:          "amd64",
		},
		Tool: report.ToolInfo{
			Name:      "copyfail-validate",
			Version:   "v0.1.0",
			Commit:    "abc1234",
			BuildDate: "2026-05-04T00:00:00Z",
		},
		Results: results,
		Summary: report.NewSummary(results),
	}
}

// mustParseRFC3339 returns the parsed time.Time or panics on bad
// input. Used as an inline literal-time builder in test fixtures.
func mustParseRFC3339(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// TestRender_JSON_Golden pins the JSON renderer's pretty-printed
// output against testdata/golden/json/basic.json. Run with -update
// to regenerate the fixture when the wire format changes
// intentionally; without -update, a diff fails the test loudly.
//
// Not parallel: depends on a specific COPYFAIL_JSON_COMPACT state.
// See withCleanEnv for the reasoning.
func TestRender_JSON_Golden(t *testing.T) {
	withCleanEnv(t, render.EnvJSONCompact, "")

	rep := fixedReport()
	var buf bytes.Buffer
	n, err := render.RenderJSON(&buf, rep)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Errorf("RenderJSON returned n=%d but wrote %d bytes", n, buf.Len())
	}

	goldenPath := filepath.Join("testdata", "golden", "json", "basic.json")
	if *updateGolden {
		writeGolden(t, goldenPath, buf.Bytes())
	}
	want := readGolden(t, goldenPath)
	if diff := cmp.Diff(string(want), buf.String()); diff != "" {
		t.Errorf("RenderJSON golden mismatch (-want +got):\n%s\n(rerun with -update to refresh)", diff)
	}
}

// TestRender_JSON_RoundTrip verifies that bytes produced by
// RenderJSON, when fed back into json.Unmarshal, reproduce the
// original Report (modulo the Generated timestamp's tz, which
// json.Unmarshal normalizes to UTC). This is the property that
// downstream consumers rely on: writing and reading a report yields
// the same logical value.
//
// Not parallel: depends on a specific COPYFAIL_JSON_COMPACT state.
func TestRender_JSON_RoundTrip(t *testing.T) {
	withCleanEnv(t, render.EnvJSONCompact, "")

	rep := fixedReport()
	var buf bytes.Buffer
	if _, err := render.RenderJSON(&buf, rep); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var got report.Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v\npayload:\n%s", err, buf.String())
	}

	// Generated round-trips with timezone preserved on Marshal but
	// json normalizes by re-parsing in UTC; compare in UTC for safety.
	want := rep
	want.Generated = want.Generated.UTC()
	gotNorm := got
	gotNorm.Generated = gotNorm.Generated.UTC()
	if !gotNorm.Generated.Equal(want.Generated) {
		t.Errorf("Generated mismatch: got=%v want=%v", gotNorm.Generated, want.Generated)
	}
	if diff := cmp.Diff(want.Results, gotNorm.Results); diff != "" {
		t.Errorf("Results mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(want.Summary, gotNorm.Summary); diff != "" {
		t.Errorf("Summary mismatch (-want +got):\n%s", diff)
	}
}

// TestRender_JSON_StableAcrossRuns is the property test for
// determinism: ten consecutive RenderJSON calls on the same Report
// must produce byte-identical output. Without this, golden tests
// would be flaky and operators couldn't compare two reports
// generated by separate runs of the same input.
//
// Not parallel: depends on a specific COPYFAIL_JSON_COMPACT state.
func TestRender_JSON_StableAcrossRuns(t *testing.T) {
	withCleanEnv(t, render.EnvJSONCompact, "")

	rep := fixedReport()
	var first []byte
	for i := 0; i < 10; i++ {
		var buf bytes.Buffer
		if _, err := render.RenderJSON(&buf, rep); err != nil {
			t.Fatalf("iteration %d: RenderJSON: %v", i, err)
		}
		if i == 0 {
			first = bytes.Clone(buf.Bytes())
			continue
		}
		if !bytes.Equal(first, buf.Bytes()) {
			t.Fatalf("iteration %d output differs from iteration 0", i)
		}
	}
}

// TestRender_JSON_CompactEnv verifies the COPYFAIL_JSON_COMPACT=1
// override: output must be a single line plus the trailing newline,
// must still parse as JSON, and must reproduce the same logical
// Report as the pretty form.
//
// Not parallel: mutates COPYFAIL_JSON_COMPACT.
func TestRender_JSON_CompactEnv(t *testing.T) {
	withCleanEnv(t, render.EnvJSONCompact, "1")

	rep := fixedReport()
	var buf bytes.Buffer
	if _, err := render.RenderJSON(&buf, rep); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("compact output missing trailing newline: %q", out)
	}
	body := strings.TrimSuffix(out, "\n")
	if strings.Contains(body, "\n") {
		t.Errorf("compact output contains internal newline:\n%s", body)
	}
	var roundtrip report.Report
	if err := json.Unmarshal([]byte(body), &roundtrip); err != nil {
		t.Errorf("compact output not parseable as JSON: %v", err)
	}
}

// TestRender_JSON_BytesWrittenMatches verifies the second return
// value (n) equals the number of bytes the writer received. Callers
// such as the CLI rely on this to log "wrote N bytes to /var/...".
//
// Not parallel: depends on a specific COPYFAIL_JSON_COMPACT state.
func TestRender_JSON_BytesWrittenMatches(t *testing.T) {
	withCleanEnv(t, render.EnvJSONCompact, "")

	var buf bytes.Buffer
	n, err := render.RenderJSON(&buf, fixedReport())
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if int64(buf.Len()) != n {
		t.Errorf("buf.Len()=%d, n=%d; expected equal", buf.Len(), n)
	}
}

// TestRender_JSON_WriterError verifies that a writer that fails on
// Write surfaces a wrapped ErrRender to the caller, with the original
// error still reachable via errors.Is.
//
// Not parallel: depends on a specific COPYFAIL_JSON_COMPACT state.
func TestRender_JSON_WriterError(t *testing.T) {
	withCleanEnv(t, render.EnvJSONCompact, "")

	want := errors.New("disk full")
	w := &errWriter{err: want}
	_, err := render.RenderJSON(w, fixedReport())
	if err == nil {
		t.Fatal("RenderJSON: nil error on writer failure")
	}
	if !errors.Is(err, render.ErrRender) {
		t.Errorf("err not wrapped with ErrRender: %v", err)
	}
	if !errors.Is(err, want) {
		t.Errorf("original writer error lost in wrapping: %v", err)
	}
}

// errWriter is an io.Writer that always fails. Used by error-path
// tests across this package.
type errWriter struct {
	err error
}

// Write satisfies io.Writer by returning err for every call.
func (e *errWriter) Write(_ []byte) (int, error) { return 0, e.err }

// withCleanEnv sets env[key] to value (or unsets it when value is
// empty) and restores the prior value on test cleanup.
//
// Tests that call this MUST NOT call t.Parallel() — env state is
// process-global and parallel readers would race the writer. The
// stdlib's t.Setenv enforces the same rule by panicking; this helper
// avoids t.Setenv only because t.Setenv has no "unset" mode (empty
// string sets to ""). Every env-touching test in this package is
// therefore serialized rather than racing against its peers on the
// process-global os.Environ.
func withCleanEnv(t *testing.T, key, value string) {
	t.Helper()
	prev, hadPrev := os.LookupEnv(key)
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(key, prev)
			return
		}
		_ = os.Unsetenv(key)
	})
	if value == "" {
		_ = os.Unsetenv(key)
		return
	}
	_ = os.Setenv(key, value)
}

// readGolden reads a golden file relative to the test binary's cwd,
// failing the test if the file is missing.
func readGolden(t *testing.T, path string) []byte {
	t.Helper()
	// #nosec G304 -- path is a fixed test fixture under testdata/.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %q: %v", path, err)
	}
	return b
}

// writeGolden writes data to the given golden path, creating
// intermediate directories. Used only when -update is set.
func writeGolden(t *testing.T, path string, data []byte) {
	t.Helper()
	// #nosec G301 -- testdata/golden directories ship with the source
	// tree and need to be readable by humans inspecting the diff.
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(path), err)
	}
	// #nosec G306 -- golden fixtures are world-readable by design;
	// they're committed to git as plain text.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write golden %q: %v", path, err)
	}
}
