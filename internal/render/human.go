// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/polyglotdev/copyfail-validation/report"
)

// EnvNoColor disables ANSI color in the human renderer when set to any
// non-empty value. Mirrors the cross-tool NO_COLOR convention
// (https://no-color.org/).
const EnvNoColor = "NO_COLOR"

// ANSI color codes used by the human renderer. SGR resets between rows
// keep colored runs from bleeding across status lines.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiGreen  = "\x1b[32m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

// statusLabel returns the right-padded five-character status token
// printed at the start of every per-result line. Keeping the width
// constant keeps the check_id column aligned across rows.
//
// Unknown states render as "?    " so a malformed Result is visually
// obvious in operator output instead of silently disappearing.
func statusLabel(s report.State) string {
	switch s {
	case report.StatePass:
		return "OK   "
	case report.StateFail:
		return "FAIL "
	case report.StateSkip:
		return "SKIP "
	case report.StateError:
		return "ERROR"
	default:
		return "?    "
	}
}

// statusColor returns the ANSI color escape (or empty string when
// color is disabled) for the given State.
func statusColor(s report.State, useColor bool) string {
	if !useColor {
		return ""
	}
	switch s {
	case report.StatePass:
		return ansiGreen
	case report.StateFail:
		return ansiRed
	case report.StateSkip:
		return ansiYellow
	case report.StateError:
		return ansiRed + ansiBold
	default:
		return ansiCyan
	}
}

// shouldColor reports whether the human renderer should emit ANSI
// color escapes for output going to w. Three conditions all must hold:
//   - the NO_COLOR env var is unset (https://no-color.org/);
//   - w is an *os.File (we can't call Stat on a generic io.Writer);
//   - that file's mode reports it as a character device (TTY-ish).
//
// Bytes-buffer writers and regular files therefore get plain output by
// default, which keeps golden-file tests deterministic without any
// extra opt-out flag.
func shouldColor(w io.Writer) bool {
	if os.Getenv(EnvNoColor) != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

// RenderHuman writes rep to w as a human-readable validation report
// and returns the byte count actually written.
//
// The output shape, per spec §5 / Phase 4 task 4.3:
//
//	STATUS  check.id (severity): detail
//	...
//	validator result: PASS|FAIL
//	total: N pass=N fail=N skip=N error=N (required: pass=N fail=N error=N)
//
// STATUS is one of OK/FAIL/SKIP/ERROR (right-padded to five characters)
// and is colored with ANSI escapes when w is a TTY-like *os.File and
// the NO_COLOR env var is unset. Plain writers (bytes.Buffer, regular
// files) always get uncolored output.
//
//nolint:revive // Render* prefix is the documented contract; see RenderJSON.
func RenderHuman(w io.Writer, rep report.Report) (int64, error) {
	useColor := shouldColor(w)

	var buf bytes.Buffer
	for _, r := range rep.Results {
		writeResultLine(&buf, r, useColor)
	}
	writeFooter(&buf, rep, useColor)
	return flushAll(w, buf.Bytes())
}

// writeResultLine writes one per-result line to buf in the canonical
// format. A trailing newline is always appended. The detail column is
// omitted (no leading ": ") when both Detail and Err are empty so the
// line stays compact for clean passes.
func writeResultLine(buf *bytes.Buffer, r report.Result, useColor bool) {
	color := statusColor(r.State, useColor)
	reset := ""
	if color != "" {
		reset = ansiReset
	}

	fmt.Fprintf(buf, "%s%s%s  %s (%s)", color, statusLabel(r.State), reset, r.CheckID, r.Severity)

	detail := r.Detail
	if r.State == report.StateError && r.Err != "" {
		detail = r.Err
	}
	if detail != "" {
		fmt.Fprintf(buf, ": %s", detail)
	}
	buf.WriteByte('\n')
}

// writeFooter writes the two-line summary block to buf. The first line
// is "validator result: PASS" or "validator result: FAIL" (PASS iff
// no required failures or errors); the second line is the per-state
// tally including the Required breakdown.
func writeFooter(buf *bytes.Buffer, rep report.Report, useColor bool) {
	pass := rep.Summary.Required.Fail == 0 && rep.Summary.Required.Error == 0

	verdict := "PASS"
	color := ""
	if !pass {
		verdict = "FAIL"
	}
	if useColor {
		if pass {
			color = ansiGreen + ansiBold
		} else {
			color = ansiRed + ansiBold
		}
	}
	reset := ""
	if color != "" {
		reset = ansiReset
	}

	fmt.Fprintf(buf, "validator result: %s%s%s\n", color, verdict, reset)
	fmt.Fprintf(buf,
		"total: %d pass=%d fail=%d skip=%d error=%d (required: pass=%d fail=%d error=%d)\n",
		rep.Summary.Total,
		rep.Summary.Pass,
		rep.Summary.Fail,
		rep.Summary.Skip,
		rep.Summary.Error,
		rep.Summary.Required.Pass,
		rep.Summary.Required.Fail,
		rep.Summary.Required.Error,
	)
}
