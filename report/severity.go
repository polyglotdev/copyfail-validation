// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

// Severity classifies the operational meaning of a failed check. A failed
// Required check produces a non-zero process exit; a failed Advisory
// check is reported but does not change the exit code.
type Severity string

// Severity constants. Frozen at v1.0.0.
const (
	SeverityRequired Severity = "required"
	SeverityAdvisory Severity = "advisory"
)

// IsRequired reports whether s is SeverityRequired. Defined as a method
// (rather than a direct comparison) so that future Severity values can
// extend the "required-class" set without changing call sites.
func (s Severity) IsRequired() bool {
	return s == SeverityRequired
}
