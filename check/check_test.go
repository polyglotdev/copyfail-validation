// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package check_test

import (
	"context"
	"testing"
	"time"

	"github.com/polyglotdev/copyfail-validation/check"
	"github.com/polyglotdev/copyfail-validation/report"
)

// nominalCheck is a minimal struct that satisfies check.Check. It
// exists only to compile-time-prove the interface contract; tests in
// runner_test.go use a richer mock.
type nominalCheck struct{}

func (nominalCheck) ID() string    { return "test.nominal" }
func (nominalCheck) Title() string { return "Nominal" }
func (nominalCheck) Description() string {
	return "A trivial check used to verify the interface compiles."
}
func (nominalCheck) Severity() report.Severity                 { return report.SeverityAdvisory }
func (nominalCheck) Applicable(context.Context) (bool, string) { return true, "" }
func (nominalCheck) Run(context.Context) report.Result {
	return report.Result{
		CheckID:   "test.nominal",
		Title:     "Nominal",
		Severity:  report.SeverityAdvisory,
		State:     report.StatePass,
		StartedAt: time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC),
	}
}

// TestCheck_InterfaceSatisfaction is a compile-time pin: it asserts
// via a static type-conversion that nominalCheck satisfies check.Check.
// If a future change to the Check interface breaks this assignment
// the test binary won't compile — exactly what we want, because every
// preset check would also break and the build fails loudly rather
// than the regression slipping past the unit tests.
//
// The test does NOT call t.Parallel because the assertion is purely
// at the type level; there is no runtime work to parallelize.
func TestCheck_InterfaceSatisfaction(t *testing.T) {
	t.Parallel()
	var _ check.Check = nominalCheck{}
	var _ check.Check = (*nominalCheck)(nil)
}

// TestCheck_NominalRun exercises the nominal check end-to-end so the
// table-driven harness in runner_test.go has at least one demonstrably-
// real implementation to depend on. Pins the regression that the zero
// test struct, when run, returns a structurally complete Result with
// State=Pass and the documented identity fields populated.
func TestCheck_NominalRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		c       check.Check
		wantID  string
		wantSev report.Severity
		wantOK  bool
	}{
		{
			name:    "value receiver",
			c:       nominalCheck{},
			wantID:  "test.nominal",
			wantSev: report.SeverityAdvisory,
			wantOK:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			ctx := context.Background()

			if got := tc.c.ID(); got != tc.wantID {
				subT.Errorf("ID() = %q, want %q", got, tc.wantID)
			}
			if got := tc.c.Severity(); got != tc.wantSev {
				subT.Errorf("Severity() = %q, want %q", got, tc.wantSev)
			}
			ok, _ := tc.c.Applicable(ctx)
			if ok != tc.wantOK {
				subT.Errorf("Applicable() ok = %t, want %t", ok, tc.wantOK)
			}
			res := tc.c.Run(ctx)
			if res.State != report.StatePass {
				subT.Errorf("Run().State = %q, want %q", res.State, report.StatePass)
			}
			if res.CheckID != tc.wantID {
				subT.Errorf("Run().CheckID = %q, want %q", res.CheckID, tc.wantID)
			}
		})
	}
}
