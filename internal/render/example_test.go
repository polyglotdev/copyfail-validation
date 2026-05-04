// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/polyglotdev/copyfail-validation/internal/render"
	"github.com/polyglotdev/copyfail-validation/report"
)

// exampleReport returns a tiny deterministic Report value used by
// every Example_* test in this file. Two checks (one pass, one
// required fail) are enough to demonstrate every renderer's
// per-result output and the verdict line.
func exampleReport() report.Report {
	t := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	results := []report.Result{
		{
			StartedAt:  t,
			CheckID:    "modprobe.dry_run",
			Title:      "modprobe dry run resolves to /bin/false",
			State:      report.StatePass,
			Severity:   report.SeverityRequired,
			Detail:     "ok",
			DurationMS: 10,
		},
		{
			StartedAt:  t,
			CheckID:    "kernel.modules_loaded",
			Title:      "no copyfail modules loaded",
			State:      report.StateFail,
			Severity:   report.SeverityRequired,
			Detail:     "found 1 loaded module: copyfail",
			DurationMS: 5,
		},
	}
	return report.Report{
		SchemaVersion: report.SchemaVersionCurrent,
		Generated:     t,
		Host:          report.HostInfo{Hostname: "example-host"},
		Tool:          report.ToolInfo{Name: "copyfail-validate", Version: "v0.1.0", Commit: "abc1234"},
		Results:       results,
		Summary:       report.NewSummary(results),
	}
}

// ExampleRenderJSON shows the canonical pretty-printed JSON form a
// caller sees when the COPYFAIL_JSON_COMPACT env var is unset (the
// default). Operators use this form for debugging via jq; CI
// pipelines flip COPYFAIL_JSON_COMPACT=1 for one-line shipping.
func ExampleRenderJSON() {
	// Ensure determinism — clear the compact override.
	prev, hadPrev := os.LookupEnv(render.EnvJSONCompact)
	defer func() {
		if hadPrev {
			_ = os.Setenv(render.EnvJSONCompact, prev)
		} else {
			_ = os.Unsetenv(render.EnvJSONCompact)
		}
	}()
	_ = os.Unsetenv(render.EnvJSONCompact)

	var buf bytes.Buffer
	if _, err := render.RenderJSON(&buf, exampleReport()); err != nil {
		fmt.Println("error:", err)
		return
	}
	// Print only the first line so the example stays short.
	first := strings.SplitN(buf.String(), "\n", 2)[0]
	fmt.Println(first)
	// Output:
	// {
}

// ExampleRenderHuman shows the per-result + footer shape of the
// human renderer when the writer is not a TTY (here, a bytes.Buffer)
// so output is plain ANSI-free text.
func ExampleRenderHuman() {
	var buf bytes.Buffer
	if _, err := render.RenderHuman(&buf, exampleReport()); err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Print(buf.String())
	// Output:
	// OK     modprobe.dry_run (required): ok
	// FAIL   kernel.modules_loaded (required): found 1 loaded module: copyfail
	// validator result: FAIL
	// total: 2 pass=1 fail=1 skip=0 error=0 (required: pass=1 fail=1 error=0)
}

// ExampleRenderSARIF shows the first few characteristic lines of
// the SARIF v2.1.0 document the renderer emits. The full document
// is large; the example trims to the first two lines.
func ExampleRenderSARIF() {
	var buf bytes.Buffer
	if _, err := render.RenderSARIF(&buf, exampleReport()); err != nil {
		fmt.Println("error:", err)
		return
	}
	lines := strings.SplitN(buf.String(), "\n", 4)
	for _, l := range lines[:3] {
		fmt.Println(l)
	}
	// Output:
	// {
	//   "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
	//   "version": "2.1.0",
}

// ExampleRenderPrometheus shows the first few metric lines a
// node_exporter textfile collector would scrape. Operators rarely
// read these directly — the example exists to pin the canonical
// metric naming and label shape.
func ExampleRenderPrometheus() {
	var buf bytes.Buffer
	if _, err := render.RenderPrometheus(&buf, exampleReport()); err != nil {
		fmt.Println("error:", err)
		return
	}
	lines := strings.Split(buf.String(), "\n")
	for _, l := range lines[:3] {
		fmt.Println(l)
	}
	// Output:
	// # HELP copyfail_validator_check_state Result of one mitigation check (1 = current state).
	// # TYPE copyfail_validator_check_state gauge
	// copyfail_validator_check_state{check_id="kernel.modules_loaded",severity="required",state="pass"} 0
}

// ExampleWriteTextfileAtomic shows the canonical cron+textfile
// usage: render to a temp directory, then read the resulting .prom
// file back to verify it lands at the expected path.
func ExampleWriteTextfileAtomic() {
	dir, err := os.MkdirTemp("", "copyfail-example-*")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if _, werr := render.WriteTextfileAtomic(dir, "copyfail_validator", exampleReport()); werr != nil {
		fmt.Println("error:", werr)
		return
	}

	final := filepath.Join(dir, "copyfail_validator.prom")
	st, err := os.Stat(final)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("filename:", st.Name())
	// Output:
	// filename: copyfail_validator.prom
}
