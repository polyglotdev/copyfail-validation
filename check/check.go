// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"context"

	"github.com/polyglotdev/copyfail-validation/report"
)

// Check is the unit of validation. Concrete implementations live under
// preset/<name>/ and supply the actual probing logic; the Runner in
// this package orchestrates a slice of them.
//
// Implementations MUST be:
//
//   - Pure of global state. Two Runner.Run invocations on the same
//     []Check slice MUST produce the same Report (modulo timestamps and
//     anything genuinely host-volatile like /proc/loadavg). A check
//     that mutates a package-level var across runs breaks this
//     contract.
//   - Safe to call concurrently with other Checks. The Runner fan-outs
//     into a worker pool of size Runner.Concurrency; two siblings may
//     execute simultaneously on different goroutines. A check that
//     shares mutable state with its peers via package globals is
//     broken even when its tests pass — the race detector is the
//     enforcement mechanism (see runner_concurrency_test.go).
//   - Read-only with respect to host state. A Check that modifies
//     /proc, /sys, /etc, /var, or any subprocess's environment is a
//     bug. The Runner does not enforce this — reviewers and
//     integration tests do.
//
// The Runner discovers behavior by composition. Each method is called
// in a known order: ID/Title/Description/Severity may be called any
// number of times (the Runner reads them once per invocation, but
// other consumers — renderers, CLI flags — call them too). Applicable
// is called exactly ONCE per Runner.Run invocation, before Run. Run
// is called exactly ZERO times if Applicable returned (false, _),
// exactly ONCE otherwise.
type Check interface {
	// ID is a stable, machine-readable identifier (e.g.
	// "modprobe.dry_run"). It MUST NOT change once a preset has
	// shipped — the ID appears in JSON report output, SARIF rule IDs,
	// and Prometheus metric labels. Renaming an ID is a major schema
	// bump (see report.SchemaVersionCurrent).
	ID() string

	// Title is a short human-readable name (≤80 chars). Shown in the
	// SARIF rule.shortDescription and in the human-format report's
	// per-result lines.
	Title() string

	// Description is a longer human-readable explanation suitable for
	// SARIF rule.help.text. May be multi-line. Implementations should
	// describe what the check probes, why it matters, and what an
	// operator should do if the check fails.
	Description() string

	// Severity is report.SeverityRequired or report.SeverityAdvisory.
	// Required failures change the process exit code; advisory failures
	// only appear in the report. The exit code is computed by the CLI
	// from Report.Summary.Required, NOT by the Runner.
	Severity() report.Severity

	// Applicable reports whether this check should run on the current
	// host. Returning (false, reason) produces a StateSkip Result with
	// the reason recorded in Detail; Run is NOT called. Returning
	// (true, "") proceeds to Run.
	//
	// Applicable MUST honor ctx.Done(). It MAY perform short, read-only
	// probes (e.g., checking whether a binary is present in $PATH, or
	// stat'ing a file), but MUST NOT do expensive work — defer that to
	// Run, where the per-check timeout applies.
	Applicable(ctx context.Context) (ok bool, reason string)

	// Run executes the check. It MUST honor ctx cancellation. The
	// returned Result MUST have CheckID, Title, Severity, State, and
	// StartedAt populated; Detail and Evidence are optional but
	// strongly recommended. The Runner overwrites DurationMS, so
	// implementations should not bother computing it.
	Run(ctx context.Context) report.Result
}
