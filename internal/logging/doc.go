// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package logging constructs the *slog.Logger that the rest of the
// validator uses. Production code calls New(Options{...}) exactly once
// at CLI startup; subordinate components attach per-component context
// via slog.Logger.With() so every log line carries the run_id, tool,
// version, and component-specific attributes for fleet correlation.
//
// # Why a constructor and not just slog.Default
//
// The validator must produce structured JSON on stderr so the report on
// stdout stays clean for `jq` (spec §6 output stream discipline). The
// stdlib's slog.Default writes text to stderr by default; building the
// JSON handler with the right level + AddSource flag is one block of
// boilerplate that every test would otherwise re-implement. Centralizing
// it here lets every test capture log output to a bytes.Buffer with
// identical setup to production.
//
// # Verbosity mapping (CLI -v / -vv flags)
//
// Verbosity 0 (default) → slog.LevelWarn — only warnings and errors
// land on stderr; the operator-facing default for fleet-wide rollouts
// where chatter is noise.
//
// Verbosity 1 (-v) → slog.LevelInfo — one line per check outcome plus
// warnings and errors; the typical interactive default.
//
// Verbosity 2+ (-vv) → slog.LevelDebug PLUS AddSource — emits file:line
// on every line for post-mortem debugging. AddSource is deliberately
// gated behind verbosity 2 because the file:line annotation is ~30
// bytes per line and would dominate the log volume at info/warn levels.
//
// # run_id and the no-uuid commitment
//
// Every log line carries a run_id base attribute so the fleet's log
// aggregator can correlate one validator run across thousands of hosts.
// When the caller does not supply a RunID, New generates 16 bytes of
// crypto/rand-sourced randomness and hex-encodes them (32 hex chars).
// This is deliberately NOT a github.com/google/uuid dependency: 16
// random bytes is plenty of entropy for run correlation, and the v0.1
// runtime is committed to stdlib-only (the only non-stdlib import is
// google/go-cmp, used in tests).
//
// # Spec reference
//
// See docs/superpowers/specs/2026-05-04-copyfail-validation-design.md
// §6 (output stream discipline) and §8.1 (structured logging contract).
package logging
