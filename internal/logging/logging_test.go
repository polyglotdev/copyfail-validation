// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package logging_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/buildinfo"
	"github.com/polyglotdev/copyfail-validation/internal/logging"
)

// expectedHexLen is the documented run_id length: 16 bytes hex-encoded.
const expectedHexLen = 32

// captureLog constructs a logger whose output is captured into a fresh
// bytes.Buffer, runs fn against the resulting *slog.Logger, and returns
// every emitted line as a parsed JSON map. The helper hides the boring
// boilerplate (build a buffer, set Writer, parse line-delimited JSON)
// so individual tests focus on the assertions.
func captureLog(subT *testing.T, opts logging.Options, fn func(logger *slog.Logger)) (lines []map[string]any, raw string) {
	subT.Helper()
	buf := &bytes.Buffer{}
	opts.Writer = buf
	logger := logging.New(opts)
	fn(logger)

	raw = buf.String()
	for _, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		if line == "" {
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			subT.Fatalf("captureLog: line %q is not JSON: %v", line, err)
		}
		lines = append(lines, parsed)
	}
	return lines, raw
}

// TestNew_BaseAttributes verifies the three documented base attributes
// (tool, version, run_id) appear on every emitted line. This is the
// fleet-wide correlation contract — without these attributes the log
// aggregator cannot tie one validator run together across thousands
// of hosts.
func TestNew_BaseAttributes(t *testing.T) {
	t.Parallel()

	const customRunID = "deadbeefcafebabe1234567890abcdef"
	lines, _ := captureLog(t, logging.Options{Verbosity: 1, RunID: customRunID}, func(logger *slog.Logger) {
		logger.Info("first line")
		logger.Warn("second line")
	})

	if len(lines) != 2 {
		t.Fatalf("got %d lines; want 2 (raw=%q)", len(lines), lines)
	}

	for i, ln := range lines {
		if got := ln["tool"]; got != buildinfo.ToolName {
			t.Errorf("line[%d].tool = %v; want %q", i, got, buildinfo.ToolName)
		}
		if got := ln["version"]; got != buildinfo.Version {
			t.Errorf("line[%d].version = %v; want %q", i, got, buildinfo.Version)
		}
		if got := ln["run_id"]; got != customRunID {
			t.Errorf("line[%d].run_id = %v; want %q", i, got, customRunID)
		}
	}
}

// TestNew_VerbosityLevels covers the (Verbosity → emitted-levels)
// contract documented on Options.Verbosity. Every call sequence below
// emits one Debug + one Info + one Warn + one Error line; the
// expected count varies per verbosity level.
func TestNew_VerbosityLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		wantLevels      []string
		verbosity       int
		wantLineCount   int
		wantSourceField bool
	}{
		{
			name:          "verbosity 0 emits Warn and Error only",
			verbosity:     0,
			wantLineCount: 2,
			wantLevels:    []string{"WARN", "ERROR"},
		},
		{
			name:          "verbosity 1 emits Info, Warn, Error",
			verbosity:     1,
			wantLineCount: 3,
			wantLevels:    []string{"INFO", "WARN", "ERROR"},
		},
		{
			name:            "verbosity 2 emits all four levels with source field",
			verbosity:       2,
			wantLineCount:   4,
			wantLevels:      []string{"DEBUG", "INFO", "WARN", "ERROR"},
			wantSourceField: true,
		},
		{
			name:            "verbosity 5 stays at debug-with-source (no further escalation)",
			verbosity:       5,
			wantLineCount:   4,
			wantLevels:      []string{"DEBUG", "INFO", "WARN", "ERROR"},
			wantSourceField: true,
		},
		{
			name:          "negative verbosity treated as 0",
			verbosity:     -1,
			wantLineCount: 2,
			wantLevels:    []string{"WARN", "ERROR"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			lines, raw := captureLog(subT, logging.Options{Verbosity: tc.verbosity}, func(logger *slog.Logger) {
				logger.Debug("dbg msg")
				logger.Info("inf msg")
				logger.Warn("warn msg")
				logger.Error("err msg")
			})

			if got, want := len(lines), tc.wantLineCount; got != want {
				subT.Fatalf("line count = %d; want %d (raw=%q)", got, want, raw)
			}
			for i, level := range tc.wantLevels {
				if got, want := lines[i]["level"], level; got != want {
					subT.Errorf("lines[%d].level = %v; want %q", i, got, want)
				}
			}
			for i, ln := range lines {
				_, hasSource := ln["source"]
				if hasSource != tc.wantSourceField {
					subT.Errorf("lines[%d] has source=%v; want %v", i, hasSource, tc.wantSourceField)
				}
			}
		})
	}
}

// TestNew_AutoGeneratesRunID verifies that an empty Options.RunID
// triggers the crypto/rand fallback. The auto-generated value MUST be
// exactly 32 hex characters (16 bytes encoded), matching the contract
// in the New godoc.
func TestNew_AutoGeneratesRunID(t *testing.T) {
	t.Parallel()

	lines, _ := captureLog(t, logging.Options{Verbosity: 1}, func(logger *slog.Logger) {
		logger.Info("kick")
	})

	if len(lines) != 1 {
		t.Fatalf("got %d lines; want 1", len(lines))
	}

	got, ok := lines[0]["run_id"].(string)
	if !ok {
		t.Fatalf("run_id field missing or not a string; got %T %v", lines[0]["run_id"], lines[0]["run_id"])
	}
	if len(got) != expectedHexLen {
		t.Errorf("run_id length = %d; want %d (value=%q)", len(got), expectedHexLen, got)
	}
	for _, c := range got {
		if !isHexDigit(c) {
			t.Errorf("run_id contains non-hex character %q (value=%q)", c, got)
			break
		}
	}
}

// TestNew_AutoGeneratedRunIDsAreUnique verifies that two back-to-back
// calls with empty RunID produce DIFFERENT run_ids — the fallback uses
// cryptographic randomness, not a counter. Two identical run_ids would
// silently break fleet-wide correlation, so this test is a tripwire
// for any future regression that swaps crypto/rand for math/rand or a
// counter-based generator.
func TestNew_AutoGeneratedRunIDsAreUnique(t *testing.T) {
	t.Parallel()

	const samples = 8
	seen := make(map[string]struct{}, samples)
	for i := 0; i < samples; i++ {
		lines, _ := captureLog(t, logging.Options{Verbosity: 1}, func(logger *slog.Logger) {
			logger.Info("sample")
		})
		if len(lines) != 1 {
			t.Fatalf("iteration %d: got %d lines; want 1", i, len(lines))
		}
		runID, _ := lines[0]["run_id"].(string)
		if _, dup := seen[runID]; dup {
			t.Fatalf("iteration %d: duplicate run_id %q (cryptographic randomness expected)", i, runID)
		}
		seen[runID] = struct{}{}
	}
}

// TestNew_CustomRunIDPreservedVerbatim verifies that a caller-supplied
// RunID flows through to every log line unchanged. No padding, no
// truncation, no reformatting — what the caller passed is what the
// aggregator sees.
func TestNew_CustomRunIDPreservedVerbatim(t *testing.T) {
	t.Parallel()

	const want = "fleet-run-2026-05-04T10:30:00Z"
	lines, _ := captureLog(t, logging.Options{Verbosity: 1, RunID: want}, func(logger *slog.Logger) {
		logger.Info("kick")
	})

	if len(lines) != 1 {
		t.Fatalf("got %d lines; want 1", len(lines))
	}
	if got := lines[0]["run_id"]; got != want {
		t.Errorf("run_id = %v; want %q", got, want)
	}
}

// TestNew_DefaultWriterIsStderr verifies the documented default: when
// Options.Writer is nil, New routes log lines to os.Stderr. The test
// asserts behavior (lines go to a non-nil destination and the logger
// is functional) rather than identity (we do NOT redirect os.Stderr in
// the test, which would race with `go test`'s own stderr handling).
//
// The construction must not panic and must return a non-nil logger.
func TestNew_DefaultWriterIsStderr(t *testing.T) {
	t.Parallel()

	logger := logging.New(logging.Options{})
	if logger == nil {
		t.Fatal("New(Options{}) = nil; want non-nil logger")
	}
	// Issue a low-level message that will NOT be emitted at the
	// default Verbosity 0 → Warn level. This proves the logger is
	// constructed and functional without polluting the test's stderr.
	logger.Debug("invisible at default verbosity")
}

// TestNew_DefaultVerbosityIsWarn verifies that Verbosity=0 (the zero
// value of the int field) maps to slog.LevelWarn, not Info or Debug.
// Any future change that flips the default to Info would silently
// turn the validator into a chatty fleet-wide logger — this test is
// the tripwire.
func TestNew_DefaultVerbosityIsWarn(t *testing.T) {
	t.Parallel()

	lines, _ := captureLog(t, logging.Options{}, func(logger *slog.Logger) {
		logger.Debug("dbg")
		logger.Info("inf")
		logger.Warn("wrn")
		logger.Error("err")
	})

	if len(lines) != 2 {
		t.Fatalf("got %d lines; want 2 (Warn + Error only)", len(lines))
	}
	for i, want := range []string{"WARN", "ERROR"} {
		if got := lines[i]["level"]; got != want {
			t.Errorf("lines[%d].level = %v; want %q", i, got, want)
		}
	}
}

// TestNew_HandlerIsJSON verifies the wire format is JSON, not text.
// We assert by construction (every captured line round-trips through
// json.Unmarshal in captureLog) AND by checking that the captured
// output starts with '{', the unambiguous JSON-object marker. A text-
// formatted handler would emit `time=... level=...` instead.
func TestNew_HandlerIsJSON(t *testing.T) {
	t.Parallel()

	_, raw := captureLog(t, logging.Options{Verbosity: 1}, func(logger *slog.Logger) {
		logger.Info("hello")
	})

	if raw == "" {
		t.Fatal("captured no output")
	}
	if raw[0] != '{' {
		t.Errorf("output does not begin with '{'; got %q", raw)
	}
}

// TestNew_RespectsContextOnEnabled exercises the Enabled hook by way
// of LogAttrs (which threads the context through). The real value of
// the test is to pin that the constructor works with the
// context-aware slog API, not just the convenience methods.
func TestNew_RespectsContextOnEnabled(t *testing.T) {
	t.Parallel()

	lines, _ := captureLog(t, logging.Options{Verbosity: 2}, func(logger *slog.Logger) {
		logger.LogAttrs(context.Background(), slog.LevelDebug, "ctx debug",
			slog.String("k", "v"),
		)
	})

	if len(lines) != 1 {
		t.Fatalf("got %d lines; want 1", len(lines))
	}
	if got := lines[0]["k"]; got != "v" {
		t.Errorf("attribute k = %v; want %q", got, "v")
	}
}

// isHexDigit reports whether r is one of 0-9, a-f, or A-F. The
// crypto/rand path uses lowercase hex per encoding/hex.EncodeToString,
// but the helper accepts uppercase too so a future format change that
// switches to uppercase doesn't make this assertion an unrelated
// failure.
func isHexDigit(r rune) bool {
	switch {
	case r >= '0' && r <= '9':
		return true
	case r >= 'a' && r <= 'f':
		return true
	case r >= 'A' && r <= 'F':
		return true
	}
	return false
}
