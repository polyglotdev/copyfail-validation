// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/polyglotdev/copyfail-validation/report"

// Process exit codes (frozen at v1.0.0 per spec §6).
//
// The CLI MUST emit one of these codes; any other value is a bug. The
// codes track sysexits.h conventions where applicable (64 for usage,
// 128+signal for interrupts) and add a small set of validator-specific
// codes (2, 3, 4) so a fleet-wide aggregator can bucket hosts by
// posture without parsing the JSON report.
const (
	// exitOK is returned when every required check returned StatePass.
	// Advisory-severity Fail / Skip / Error are tolerated and do not
	// affect this code (spec §6).
	exitOK = 0

	// exitMitigationGap is returned when at least one required check
	// returned StateFail. The host has a definite mitigation gap;
	// operators page on this in their alerting rules.
	exitMitigationGap = 2

	// exitToolError is returned when the tool itself failed before any
	// check could run (could not gather hostinfo, could not open the
	// output file, could not render). The host posture is unknown.
	exitToolError = 3

	// exitCheckError is returned when at least one required check
	// returned StateError AND no required check returned StateFail.
	// Treat the host posture as Unknown — we could not fully validate,
	// but we have no positive evidence of a gap. Subordinate to
	// exitMitigationGap because a definite Fail outranks an
	// indeterminate Error.
	exitCheckError = 4

	// exitUsage is returned for bad CLI flag values, conflicting
	// --only/--skip filters, or an unknown --format. Matches
	// sysexits.h's EX_USAGE.
	exitUsage = 64

	// exitInterrupted is returned when SIGINT canceled the run mid-
	// execution. POSIX 128 + 2; unifies with the shell's own
	// interpretation of `kill -INT $pid`.
	exitInterrupted = 130

	// exitTerminated is returned when SIGTERM canceled the run mid-
	// execution. POSIX 128 + 15. The CLI still writes the partial
	// Report to the chosen output before exiting (spec §6 forensic
	// value note) — operators inspecting the file see whatever the
	// Runner managed to assemble before the signal landed.
	exitTerminated = 143
)

// computeExit applies the spec §6 priority order to the required-check
// summary in rep:
//
//	Required.Fail   > 0  → exitMitigationGap (2 wins over 4)
//	Required.Error  > 0  → exitCheckError
//	otherwise            → exitOK
//
// Signal-driven exits (130 SIGINT, 143 SIGTERM) and tool-error / usage
// exits (3, 64) are NOT computed here — main wires those directly so
// they can short-circuit on conditions this function cannot see (the
// signal channel, an open-output failure that happened before WriteTo
// returned a Report at all, a filter that matched zero checks).
func computeExit(rep report.Report) int {
	if rep.Summary.Required.Fail > 0 {
		return exitMitigationGap
	}
	if rep.Summary.Required.Error > 0 {
		return exitCheckError
	}
	return exitOK
}
