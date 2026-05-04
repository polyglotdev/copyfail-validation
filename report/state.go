// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

// State is the outcome of running a single check.
//
// SARIF mapping (used by the SARIF renderer):
//
//	StatePass  → "pass"
//	StateFail  → "fail"
//	StateSkip  → "notApplicable"
//	StateError → "open"
type State string

// State constants. These string values are part of the JSON wire format
// and are frozen at v1.0.0; renaming or removing one is a major bump per
// docs/superpowers/specs/2026-05-04-copyfail-validation-design.md §5.
const (
	StatePass  State = "pass"
	StateFail  State = "fail"
	StateSkip  State = "skip"
	StateError State = "error"
)

// SARIFKind returns the SARIF v2.1.0 result.kind value corresponding to s.
// Unknown states map to "open" so unexpected values fail safely as
// "result not available" rather than as silent passes.
func (s State) SARIFKind() string {
	switch s {
	case StatePass:
		return "pass"
	case StateFail:
		return "fail"
	case StateSkip:
		return "notApplicable"
	default:
		return "open"
	}
}
