// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

import "time"

// Result is the outcome of one Check execution. The JSON tags are part
// of the public Report.SchemaVersion contract; do not rename without a
// schema major bump (see docs/schema.md).
//
// Field ordering favors compact GC scan ranges over source-of-truth
// ordering; the JSON tags preserve the wire-format ordering callers see.
type Result struct {
	// StartedAt is the wall-clock time the check began. Serialized as
	// RFC3339 with the original timezone offset preserved.
	StartedAt time.Time `json:"started_at"`

	// Evidence is structured artifacts the check captured (command output,
	// file paths, parsed values). Optional. Implementations should keep
	// values JSON-serializable scalars or maps; nested types must marshal
	// stably across runs.
	Evidence map[string]any `json:"evidence,omitempty"`

	// CheckID is the stable, machine-readable identifier of the check
	// that produced this Result. It appears as the SARIF rule ID and as
	// a Prometheus label value, so it is frozen across schema majors.
	CheckID string `json:"check_id"`

	// Title is a short human-readable name (≤80 chars).
	Title string `json:"title"`

	// State is the outcome category.
	State State `json:"state"`

	// Severity classifies whether a failed Result affects the process exit code.
	Severity Severity `json:"severity"`

	// Detail is an operator-readable one-line summary. Optional.
	Detail string `json:"detail,omitempty"`

	// Err is non-empty iff State == StateError. Holds the operator-readable
	// error message; the wrapped error chain is logged separately via slog.
	Err string `json:"error,omitempty"`

	// DurationMS is the elapsed wall-clock time of the check, in milliseconds.
	DurationMS int64 `json:"duration_ms"`
}
