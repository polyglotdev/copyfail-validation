// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/polyglotdev/copyfail-validation/report"
)

// Prometheus metric name constants (spec §8.2). Frozen at v1.0.0;
// renaming any of these is a major bump because operator dashboards
// query them by name.
const (
	metricCheckState           = "copyfail_validator_check_state"
	metricCheckDurationSeconds = "copyfail_validator_check_duration_seconds"
	metricSummary              = "copyfail_validator_summary"
	metricRequiredFailures     = "copyfail_validator_required_failures"
	metricLastRunTimestamp     = "copyfail_validator_last_run_timestamp_seconds"
	metricBuildInfo            = "copyfail_validator_build_info"
)

// promExtension is the file extension required by node_exporter's
// textfile collector. Files ending in any other extension are ignored.
const promExtension = ".prom"

// promStateValues lists the four state labels the one-hot
// _check_state metric emits per check, in stable order. Sorting at
// emit time rather than re-sorting on every iteration keeps output
// deterministic and avoids surprising operators reading raw .prom
// files in a text editor.
var promStateValues = []report.State{
	report.StatePass,
	report.StateFail,
	report.StateSkip,
	report.StateError,
}

// RenderPrometheus writes rep to w in the Prometheus textfile
// exposition format and returns the byte count actually written.
//
// The metric set, frozen at v1.0.0 (spec §8.2):
//   - copyfail_validator_check_state{check_id, severity, state} — gauge,
//     one-hot encoded: for each check the row matching its actual State
//     has value 1 and the other three rows have value 0.
//   - copyfail_validator_check_duration_seconds{check_id} — gauge,
//     wall-clock check duration converted from milliseconds.
//   - copyfail_validator_summary{outcome} — gauge, four rows for
//     pass/fail/skip/error counts.
//   - copyfail_validator_required_failures — gauge, scalar count of
//     required failures (drives paging via the spec's example alert).
//   - copyfail_validator_last_run_timestamp_seconds — gauge, the
//     Generated time as Unix seconds.
//   - copyfail_validator_build_info{version,commit,go_version} — gauge,
//     always 1, with the build identity in labels.
//
// Output order is deterministic: checks are sorted by CheckID before
// emission so the file is byte-identical across runs given the same
// Report.
//
//nolint:revive // Render* prefix is the documented contract; see RenderJSON.
func RenderPrometheus(w io.Writer, rep report.Report) (int64, error) {
	var buf bytes.Buffer

	writeCheckStateMetric(&buf, rep.Results)
	writeCheckDurationMetric(&buf, rep.Results)
	writeSummaryMetric(&buf, rep.Summary)
	writeRequiredFailuresMetric(&buf, rep.Summary)
	writeLastRunMetric(&buf, rep)
	writeBuildInfoMetric(&buf, rep.Tool)

	return flushAll(w, buf.Bytes())
}

// writeCheckStateMetric emits the one-hot _check_state metric.
// Results are sorted by CheckID so the section is stable across runs.
func writeCheckStateMetric(buf *bytes.Buffer, results []report.Result) {
	writeHelp(buf, metricCheckState, "Result of one mitigation check (1 = current state).")
	writeType(buf, metricCheckState, "gauge")

	sorted := sortedByCheckID(results)
	for _, r := range sorted {
		for _, s := range promStateValues {
			val := 0
			if r.State == s {
				val = 1
			}
			fmt.Fprintf(buf, "%s{check_id=%s,severity=%s,state=%s} %d\n",
				metricCheckState,
				promLabelValue(r.CheckID),
				promLabelValue(string(r.Severity)),
				promLabelValue(string(s)),
				val,
			)
		}
	}
	buf.WriteByte('\n')
}

// writeCheckDurationMetric emits one row per check carrying its
// wall-clock duration in seconds (the Prometheus convention even
// though the source field is milliseconds).
func writeCheckDurationMetric(buf *bytes.Buffer, results []report.Result) {
	writeHelp(buf, metricCheckDurationSeconds, "Time spent running each check.")
	writeType(buf, metricCheckDurationSeconds, "gauge")

	sorted := sortedByCheckID(results)
	for _, r := range sorted {
		seconds := float64(r.DurationMS) / 1000.0
		fmt.Fprintf(buf, "%s{check_id=%s} %s\n",
			metricCheckDurationSeconds,
			promLabelValue(r.CheckID),
			formatFloat(seconds),
		)
	}
	buf.WriteByte('\n')
}

// writeSummaryMetric emits four rows (one per outcome) carrying the
// integer counts from Summary.
func writeSummaryMetric(buf *bytes.Buffer, s report.Summary) {
	writeHelp(buf, metricSummary, "Summary of last validation run.")
	writeType(buf, metricSummary, "gauge")
	fmt.Fprintf(buf, "%s{outcome=%s} %d\n", metricSummary, promLabelValue("pass"), s.Pass)
	fmt.Fprintf(buf, "%s{outcome=%s} %d\n", metricSummary, promLabelValue("fail"), s.Fail)
	fmt.Fprintf(buf, "%s{outcome=%s} %d\n", metricSummary, promLabelValue("skip"), s.Skip)
	fmt.Fprintf(buf, "%s{outcome=%s} %d\n", metricSummary, promLabelValue("error"), s.Error)
	buf.WriteByte('\n')
}

// writeRequiredFailuresMetric emits the scalar that drives the
// paging alert from spec §8.2.
func writeRequiredFailuresMetric(buf *bytes.Buffer, s report.Summary) {
	writeHelp(buf, metricRequiredFailures, "Required-check failures (drives paging).")
	writeType(buf, metricRequiredFailures, "gauge")
	fmt.Fprintf(buf, "%s %d\n", metricRequiredFailures, s.Required.Fail)
	buf.WriteByte('\n')
}

// writeLastRunMetric emits Generated as a Unix epoch (seconds). The
// Prometheus convention permits fractional seconds; we use integer
// seconds here because the rest of the validator works at second
// granularity anyway.
func writeLastRunMetric(buf *bytes.Buffer, rep report.Report) {
	writeHelp(buf, metricLastRunTimestamp, "Unix time of last successful run.")
	writeType(buf, metricLastRunTimestamp, "gauge")
	fmt.Fprintf(buf, "%s %d\n", metricLastRunTimestamp, rep.Generated.Unix())
	buf.WriteByte('\n')
}

// writeBuildInfoMetric emits the version/commit/go-version label
// triple. Value is always 1; consumers select on the labels.
func writeBuildInfoMetric(buf *bytes.Buffer, t report.ToolInfo) {
	writeHelp(buf, metricBuildInfo, "Build info as labels (value always 1).")
	writeType(buf, metricBuildInfo, "gauge")
	fmt.Fprintf(buf, "%s{version=%s,commit=%s,go_version=%s} 1\n",
		metricBuildInfo,
		promLabelValue(t.Version),
		promLabelValue(t.Commit),
		promLabelValue(runtime.Version()),
	)
}

// writeHelp emits a "# HELP" comment for the given metric name.
func writeHelp(buf *bytes.Buffer, name, help string) {
	fmt.Fprintf(buf, "# HELP %s %s\n", name, help)
}

// writeType emits a "# TYPE" comment for the given metric name.
func writeType(buf *bytes.Buffer, name, kind string) {
	fmt.Fprintf(buf, "# TYPE %s %s\n", name, kind)
}

// promLabelValue returns the Prometheus-quoted form of v with the
// three required escapes: `\` → `\\`, `"` → `\"`, `\n` → `\n`. The
// returned string includes the surrounding double quotes; callers
// concatenate it directly into the {label=...} expression.
func promLabelValue(v string) string {
	var b strings.Builder
	b.Grow(len(v) + 2)
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// sortedByCheckID returns a copy of results sorted by CheckID. The
// input slice is not modified so callers can pass rep.Results
// directly without surprising aliasing.
func sortedByCheckID(results []report.Result) []report.Result {
	out := make([]report.Result, len(results))
	copy(out, results)
	sort.Slice(out, func(i, j int) bool {
		return out[i].CheckID < out[j].CheckID
	})
	return out
}

// formatFloat renders f as the shortest round-trippable decimal that
// reproduces it on parse. strconv.FormatFloat with -1 precision is
// the standard way to do this; we wrap it so future changes (e.g., a
// fixed precision) are localized.
func formatFloat(f float64) string {
	// Special case: integer values render without a trailing ".0" so
	// 0 renders as "0" rather than "0e+00". Prometheus accepts both,
	// but the cleaner form matches the spec example.
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}

// WriteTextfileAtomic writes the Prometheus textfile rendering of
// rep to dir/baseName.prom via a temp file and an os.Rename, so a
// node_exporter textfile collector never reads a partially-written
// file. Returns the bytes-written count and any error.
//
// The temp file is created in dir (NOT /tmp) so the rename is on the
// same filesystem, which os.Rename guarantees is atomic. The temp
// file is removed on any error (write, sync, close, or rename) so a
// failed run does not leave debris behind.
//
// The .prom extension is enforced — node_exporter ignores files with
// any other extension. Callers should pass baseName WITHOUT the
// extension; one is appended.
func WriteTextfileAtomic(dir, baseName string, rep report.Report) (int64, error) {
	if dir == "" {
		return 0, fmt.Errorf("%w: empty dir", ErrAtomicRename)
	}
	if baseName == "" {
		return 0, fmt.Errorf("%w: empty baseName", ErrAtomicRename)
	}

	suffix, err := randSuffix()
	if err != nil {
		return 0, fmt.Errorf("%w: random suffix: %w", ErrRender, err)
	}
	tmpPath := filepath.Join(dir, baseName+".tmp."+suffix)
	finalPath := filepath.Join(dir, baseName+promExtension)

	// O_EXCL ensures we never silently overwrite an existing temp
	// file; if the random suffix collided we fail loudly.
	// #nosec G304 -- dir is operator-controlled per the doc; not a tainted path.
	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("%w: open temp: %w", ErrRender, err)
	}

	n, renderErr := RenderPrometheus(tmp, rep)
	if renderErr != nil {
		closeAndRemove(tmp, tmpPath)
		return n, renderErr
	}

	if err := tmp.Sync(); err != nil {
		closeAndRemove(tmp, tmpPath)
		return n, fmt.Errorf("%w: fsync: %w", ErrRender, err)
	}
	if err := tmp.Close(); err != nil {
		// Already closed-ish; best-effort remove.
		_ = os.Remove(tmpPath)
		return n, fmt.Errorf("%w: close: %w", ErrRender, err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return n, fmt.Errorf("%w: %w", ErrAtomicRename, err)
	}
	return n, nil
}

// closeAndRemove tries to close f and remove its on-disk path. Both
// errors are intentionally swallowed: the caller is already in an
// error path with a more informative message, and we don't want to
// shadow it with a "couldn't clean up" follow-up.
func closeAndRemove(f *os.File, path string) {
	_ = f.Close()
	if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		// Ignored on purpose; see comment above.
		_ = removeErr
	}
}

// randSuffix returns 16 hex characters of cryptographically random
// suffix. We prefer crypto/rand over time-based suffixes because two
// concurrent writers in the same millisecond would otherwise collide
// on the temp file name.
func randSuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
