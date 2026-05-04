// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail

import (
	"context"

	"github.com/polyglotdev/copyfail-validation/report"
)

// NewModuleNotLoadedCheckForTest exposes a moduleNotLoadedCheck whose
// Run reads from the supplied filesystem path instead of /proc/modules.
// It exists ONLY so the per-test fixture-driven tests in copyfail_test
// can exercise the check without needing a real /proc — a privilege
// the test binary may not have. Production code MUST keep using
// All() / AllWithOptions(); the production wiring hard-codes
// /proc/modules and intentionally provides no override.
//
// Returns a closure rather than the struct so the unexported source
// path stays fully encapsulated; callers see only the report.Result
// the closure produces.
func NewModuleNotLoadedCheckForTest(module, sourcePath string) func(ctx context.Context) report.Result {
	c := moduleNotLoadedCheck{module: module}
	return func(_ context.Context) report.Result {
		return c.runWithSource(sourcePath)
	}
}
