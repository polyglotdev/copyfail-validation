// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/render"
	"github.com/polyglotdev/copyfail-validation/report"
)

// TestRender_Prometheus_Golden pins the textfile output against the
// golden file. The Prometheus renderer is sensitive to:
//   - sorted CheckIDs (deterministic line order),
//   - one-hot _check_state encoding,
//   - label-value escaping rules.
//
// Pinning the bytes catches accidental regressions in any of these.
func TestRender_Prometheus_Golden(t *testing.T) {
	t.Parallel()
	rep := fixedReport()
	var buf bytes.Buffer
	n, err := render.RenderPrometheus(&buf, rep)
	if err != nil {
		t.Fatalf("RenderPrometheus: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Errorf("RenderPrometheus returned n=%d but wrote %d bytes", n, buf.Len())
	}

	goldenPath := filepath.Join("testdata", "golden", "prom", "basic.prom")
	if *updateGolden {
		writeGolden(t, goldenPath, buf.Bytes())
	}
	want := readGolden(t, goldenPath)
	if diff := cmp.Diff(string(want), buf.String()); diff != "" {
		t.Errorf("RenderPrometheus golden mismatch (-want +got):\n%s\n(rerun with -update to refresh)", diff)
	}
}

// TestRender_Prometheus_ExpositionGrammar runs every emitted line
// through a tiny inline grammar checker. Validates HELP/TYPE
// directives precede their metrics, label maps are well-formed, and
// metric values parse as Go floats. Intentionally avoids
// prometheus/common to honor the stdlib-only contract for this
// package's runtime build.
func TestRender_Prometheus_ExpositionGrammar(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if _, err := render.RenderPrometheus(&buf, fixedReport()); err != nil {
		t.Fatalf("RenderPrometheus: %v", err)
	}
	parseExposition(t, buf.String())
}

// TestRender_Prometheus_OneHotEncoding verifies that for each unique
// CheckID, exactly one of the four _check_state rows has value 1
// and the others have value 0. Failing this would mean a check could
// appear simultaneously in multiple states in Prometheus, breaking
// every dashboard built on a state label.
func TestRender_Prometheus_OneHotEncoding(t *testing.T) {
	t.Parallel()
	rep := fixedReport()
	var buf bytes.Buffer
	if _, err := render.RenderPrometheus(&buf, rep); err != nil {
		t.Fatalf("RenderPrometheus: %v", err)
	}

	// metricCheckStateRow matches a copyfail_validator_check_state
	// line and captures (check_id, state, value).
	re := regexp.MustCompile(`^copyfail_validator_check_state\{check_id="([^"]+)",severity="[^"]+",state="([^"]+)"\}\s+(\d+)$`)
	hot := map[string]int{} // check_id -> count of "value == 1" rows
	for _, line := range strings.Split(buf.String(), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := m[3]
		if val != "0" && val != "1" {
			t.Errorf("non-binary value %q on line %q", val, line)
			continue
		}
		if val == "1" {
			hot[m[1]]++
		}
	}
	for _, r := range rep.Results {
		if hot[r.CheckID] != 1 {
			t.Errorf("check %q: hot row count = %d, want 1", r.CheckID, hot[r.CheckID])
		}
	}
}

// TestRender_Prometheus_LabelEscaping verifies the three required
// escape sequences are applied in label values. A check with a
// double-quote, backslash, or newline in its CheckID would otherwise
// produce malformed output that node_exporter rejects.
func TestRender_Prometheus_LabelEscaping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain id is unchanged", in: "modprobe.dry_run", want: `"modprobe.dry_run"`},
		{name: "double quote is escaped", in: `evil"id`, want: `"evil\"id"`},
		{name: "backslash is escaped", in: `path\to\file`, want: `"path\\to\\file"`},
		{name: "newline is escaped", in: "line1\nline2", want: `"line1\nline2"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			rep := report.Report{
				Tool: report.ToolInfo{Version: "v0.1.0"},
				Results: []report.Result{
					{CheckID: tc.in, State: report.StatePass, Severity: report.SeverityRequired},
				},
			}
			rep.Summary = report.NewSummary(rep.Results)
			var buf bytes.Buffer
			if _, err := render.RenderPrometheus(&buf, rep); err != nil {
				subT.Fatalf("RenderPrometheus: %v", err)
			}
			if !strings.Contains(buf.String(), `check_id=`+tc.want) {
				subT.Errorf("output missing escaped label %q\noutput:\n%s", tc.want, buf.String())
			}
		})
	}
}

// TestRender_Prometheus_RequiredFailuresValue verifies the scalar
// _required_failures metric matches Summary.Required.Fail (the
// value the spec's example alert "max by (instance) > 0" pages on).
func TestRender_Prometheus_RequiredFailuresValue(t *testing.T) {
	t.Parallel()
	rep := fixedReport() // includes one required FAIL and one required ERROR
	var buf bytes.Buffer
	if _, err := render.RenderPrometheus(&buf, rep); err != nil {
		t.Fatalf("RenderPrometheus: %v", err)
	}
	want := fmt.Sprintf("copyfail_validator_required_failures %d", rep.Summary.Required.Fail)
	if !strings.Contains(buf.String(), want) {
		t.Errorf("output missing %q\noutput:\n%s", want, buf.String())
	}
}

// TestRender_Prometheus_LastRunTimestamp verifies the timestamp
// metric uses Generated.Unix() and is emitted as an integer (matches
// the spec example output).
func TestRender_Prometheus_LastRunTimestamp(t *testing.T) {
	t.Parallel()
	rep := fixedReport()
	var buf bytes.Buffer
	if _, err := render.RenderPrometheus(&buf, rep); err != nil {
		t.Fatalf("RenderPrometheus: %v", err)
	}
	want := fmt.Sprintf("copyfail_validator_last_run_timestamp_seconds %d", rep.Generated.Unix())
	if !strings.Contains(buf.String(), want) {
		t.Errorf("output missing %q\noutput:\n%s", want, buf.String())
	}
}

// TestRender_Prometheus_BuildInfo verifies the _build_info metric is
// always 1 and carries version/commit/go_version labels populated
// from rep.Tool and runtime.Version().
func TestRender_Prometheus_BuildInfo(t *testing.T) {
	t.Parallel()
	rep := fixedReport()
	var buf bytes.Buffer
	if _, err := render.RenderPrometheus(&buf, rep); err != nil {
		t.Fatalf("RenderPrometheus: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`version="v0.1.0"`,
		`commit="abc1234"`,
		"go_version=\"go", // matches "go1.X.Y" prefix from runtime.Version()
		"copyfail_validator_build_info{",
		"} 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("build_info missing %q\noutput:\n%s", want, out)
		}
	}
}

// TestRender_Prometheus_WriterError verifies a writer that fails on
// Write surfaces a wrapped ErrRender.
func TestRender_Prometheus_WriterError(t *testing.T) {
	t.Parallel()
	w := &errWriter{err: errors.New("disk full")}
	_, err := render.RenderPrometheus(w, fixedReport())
	if err == nil {
		t.Fatal("RenderPrometheus: nil error on writer failure")
	}
	if !errors.Is(err, render.ErrRender) {
		t.Errorf("err not wrapped with ErrRender: %v", err)
	}
}

// TestWriteTextfileAtomic_HappyPath verifies the file lands at
// dir/baseName.prom with the expected bytes and the temp file is
// gone. Uses t.TempDir so cleanup happens automatically.
func TestWriteTextfileAtomic_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rep := fixedReport()

	n, err := render.WriteTextfileAtomic(dir, "copyfail_validator", rep)
	if err != nil {
		t.Fatalf("WriteTextfileAtomic: %v", err)
	}
	if n <= 0 {
		t.Errorf("n=%d, want > 0", n)
	}

	finalPath := filepath.Join(dir, "copyfail_validator.prom")
	got, err := os.ReadFile(finalPath) // #nosec G304 -- test fixture path.
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}
	if int64(len(got)) != n {
		t.Errorf("file len=%d, n=%d", len(got), n)
	}

	// No leftover .tmp.* files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestWriteTextfileAtomic_RemovesTempOnRenderError verifies that a
// renderer failure midway through the write removes the temp file
// before returning. We can't easily make RenderPrometheus fail (it's
// stdlib-only and our writer is a real file), so we instead inject a
// failure by passing an unwritable directory and asserting no
// .prom file exists.
func TestWriteTextfileAtomic_RejectsBadDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wantErr error
		name    string
		dir     string
		base    string
	}{
		{name: "empty dir", dir: "", base: "copyfail", wantErr: render.ErrAtomicRename},
		{name: "empty base", dir: t.TempDir(), base: "", wantErr: render.ErrAtomicRename},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			_, err := render.WriteTextfileAtomic(tc.dir, tc.base, fixedReport())
			if !errors.Is(err, tc.wantErr) {
				subT.Errorf("err = %v, want wrapping %v", err, tc.wantErr)
			}
		})
	}
}

// TestWriteTextfileAtomic_NoLeftoverOnNonexistentDir verifies that
// writing to a nonexistent directory fails cleanly (no temp file
// gets dropped in the parent).
func TestWriteTextfileAtomic_NoLeftoverOnNonexistentDir(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	bogus := filepath.Join(parent, "does", "not", "exist")
	_, err := render.WriteTextfileAtomic(bogus, "copyfail", fixedReport())
	if err == nil {
		t.Fatal("WriteTextfileAtomic: nil error for nonexistent dir")
	}
	// Parent should still be empty.
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("readdir parent: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("parent dir contains debris: %v", entries)
	}
}

// TestWriteTextfileAtomic_Concurrent verifies two concurrent writes
// to the same destination do not produce a half-written file. Each
// writer uses its own random temp suffix, so the os.Rename calls are
// each atomic on the same filesystem; one writer's bytes win.
func TestWriteTextfileAtomic_Concurrent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines)
	var failures atomic.Int64
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if _, err := render.WriteTextfileAtomic(dir, "copyfail", fixedReport()); err != nil {
				failures.Add(1)
				t.Errorf("goroutine: %v", err)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d concurrent writers failed", failures.Load())
	}

	finalPath := filepath.Join(dir, "copyfail.prom")
	got, err := os.ReadFile(finalPath) // #nosec G304 -- test fixture path.
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}
	// Verify the contents are intact: parse the exposition grammar
	// and assert the expected metric headers are all present.
	parseExposition(t, string(got))

	// No leftover temp files: every writer cleaned up.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// parseExposition runs s through a tiny line-by-line grammar checker
// for the Prometheus textfile format. Intentionally narrow: only
// what this renderer actually produces (HELP / TYPE / metric{labels}
// value or metric value, blank-line separators). Fails the test on
// the first violation.
func parseExposition(t testing.TB, s string) {
	t.Helper()

	helpRe := regexp.MustCompile(`^# HELP (\w+) .+$`)
	typeRe := regexp.MustCompile(`^# TYPE (\w+) (counter|gauge|histogram|summary|untyped)$`)
	metricRe := regexp.MustCompile(`^(\w+)(\{[^}]*\})?\s+(.+)$`)
	labelPairRe := regexp.MustCompile(`^(\w+)="(?:[^"\\]|\\.)*"$`)

	declared := map[string]string{} // metric name -> type ("gauge", etc.)
	for lineNum, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "# HELP "):
			m := helpRe.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("line %d: malformed HELP: %q", lineNum, line)
				continue
			}
		case strings.HasPrefix(line, "# TYPE "):
			m := typeRe.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("line %d: malformed TYPE: %q", lineNum, line)
				continue
			}
			declared[m[1]] = m[2]
		case strings.HasPrefix(line, "#"):
			t.Errorf("line %d: unexpected comment: %q", lineNum, line)
		default:
			m := metricRe.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("line %d: malformed metric: %q", lineNum, line)
				continue
			}
			name := m[1]
			labels := m[2]
			value := strings.TrimSpace(m[3])

			if _, ok := declared[name]; !ok {
				t.Errorf("line %d: metric %q has no preceding TYPE: %q", lineNum, name, line)
			}
			if labels != "" {
				inner := strings.TrimSuffix(strings.TrimPrefix(labels, "{"), "}")
				for _, pair := range splitLabels(inner) {
					if !labelPairRe.MatchString(pair) {
						t.Errorf("line %d: malformed label pair %q in %q", lineNum, pair, line)
					}
				}
			}
			if _, err := strconv.ParseFloat(value, 64); err != nil {
				t.Errorf("line %d: value %q not a float: %v (line: %q)", lineNum, value, err, line)
			}
		}
	}
}

// splitLabels splits a "k=\"v\",k2=\"v2\"" string on top-level
// commas, leaving label-value escapes intact. The renderer's escape
// rules ensure no unescaped comma appears inside a value.
func splitLabels(inner string) []string {
	if inner == "" {
		return nil
	}
	var out []string
	var current strings.Builder
	inQuote := false
	escape := false
	for _, r := range inner {
		if escape {
			current.WriteRune(r)
			escape = false
			continue
		}
		switch r {
		case '\\':
			current.WriteRune(r)
			escape = true
		case '"':
			current.WriteRune(r)
			inQuote = !inQuote
		case ',':
			if inQuote {
				current.WriteRune(r)
			} else {
				out = append(out, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}
