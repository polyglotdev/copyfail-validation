// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"

	"github.com/polyglotdev/copyfail-validation/internal/buildinfo"
)

// runIDByteLen is the number of crypto/rand bytes used to seed an
// auto-generated RunID. 16 bytes (128 bits) of entropy is the same
// width as a UUID v4 random component — plenty to keep run-id
// collisions far below the realistic fleet-run rate, and the resulting
// 32-character hex string fits comfortably in a slog attribute.
const runIDByteLen = 16

// debugVerbosity is the inclusive lower bound at which the JSON handler
// switches to slog.LevelDebug AND turns on AddSource. The CLI parses
// `-v`=1 and `-vv`=2; the constant is named (not inlined) so the
// mapping documented in Options.Verbosity has exactly one source of
// truth in the package.
const debugVerbosity = 2

// infoVerbosity is the inclusive lower bound at which the JSON handler
// emits Info-level lines. Below this, only Warn and Error land on
// stderr.
const infoVerbosity = 1

// Options configures the *slog.Logger constructor.
//
// Verbosity mapping (also see the package doc):
//
//   - 0 (default) → slog.LevelWarn (operator-facing default).
//   - 1           → slog.LevelInfo (the -v default).
//   - 2+          → slog.LevelDebug, with AddSource enabled.
//
// The struct is laid out for govet's fieldalignment pass: the 16-byte
// io.Writer interface header first, then the 16-byte string header,
// then the 8-byte int tail.
type Options struct {
	// Writer is where log lines go. Defaults to os.Stderr (stdout is
	// reserved for the report; spec §6 output stream discipline).
	Writer io.Writer

	// RunID is injected as a base attribute on every log line so the
	// fleet can correlate one run across thousands of hosts. If empty,
	// New generates a 16-byte random hex ID via crypto/rand. Avoid
	// bringing in a uuid dependency just for this.
	RunID string

	// Verbosity controls the slog.Level. See the type godoc for the
	// 0/1/2+ mapping.
	Verbosity int
}

// New returns a *slog.Logger configured per opts. The logger is JSON-
// formatted (matches the rest of the copyfail-validation observability
// surface — Prometheus textfile + JSON report output) and includes
// these base attributes on every line:
//
//   - tool      → buildinfo.ToolName
//   - version   → buildinfo.Version
//   - run_id    → opts.RunID (or auto-generated 32-char hex)
//
// Defaults applied to a zero-value Options:
//   - Writer    → os.Stderr
//   - RunID     → 16 random bytes from crypto/rand, hex-encoded
//   - Verbosity → 0 (slog.LevelWarn)
func New(opts Options) *slog.Logger {
	if opts.Writer == nil {
		opts.Writer = os.Stderr
	}
	if opts.RunID == "" {
		opts.RunID = generateRunID()
	}

	level, addSource := levelAndSource(opts.Verbosity)
	handler := slog.NewJSONHandler(opts.Writer, &slog.HandlerOptions{
		Level:     level,
		AddSource: addSource,
	})

	return slog.New(handler).With(
		slog.String("tool", buildinfo.ToolName),
		slog.String("version", buildinfo.Version),
		slog.String("run_id", opts.RunID),
	)
}

// levelAndSource maps verbosity to (slog.Level, AddSource flag) per the
// table in the Options.Verbosity godoc. AddSource is gated to debug-
// only because the file:line annotation is ~30 bytes per line and
// would dominate the log volume at info/warn levels.
func levelAndSource(verbosity int) (slog.Level, bool) {
	switch {
	case verbosity >= debugVerbosity:
		return slog.LevelDebug, true
	case verbosity >= infoVerbosity:
		return slog.LevelInfo, false
	default:
		return slog.LevelWarn, false
	}
}

// generateRunID returns a 32-character hex string (16 random bytes).
// crypto/rand.Read is documented to never return a short read on
// success, so the returned slice is always exactly runIDByteLen bytes
// long when err is nil. On the (effectively impossible) failure path
// the function falls back to a fixed sentinel hex string so the logger
// still receives a well-formed run_id rather than the empty string —
// an empty run_id would defeat the fleet-wide correlation contract.
func generateRunID() string {
	buf := make([]byte, runIDByteLen)
	if _, err := rand.Read(buf); err != nil {
		// Documented impossible path on every supported platform.
		// We return a recognizable fallback (32 zero bytes hex) so
		// operators can grep for it in the rare event it surfaces.
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(buf)
}
