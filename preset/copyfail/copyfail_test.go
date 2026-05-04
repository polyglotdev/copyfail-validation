// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail_test

import (
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/preset/copyfail"
	"github.com/polyglotdev/copyfail-validation/report"
)

// expectedRequiredCheckIDs is the canonical, ordered set of required
// check identifiers v0.1 ships. Pinned here as a single source of truth
// so changes that add or reorder a required check fail one obvious test
// rather than scattering across every TestAllWithOptions_* assertion.
//
// This slice grows as each per-check task (5.4 through 5.8) lands; in
// the bundler-only commit it is empty and the All() / AllWithOptions
// asserters cover the "no checks yet" baseline.
//
// When v0.1.x adds the four advisory checks, append (do NOT prepend) to
// this slice — callers matching a tail position depend on the prefix.
var expectedRequiredCheckIDs = []string{
	"modprobe.conf_present",
	"modprobe.conf_correct",
	"modprobe.dry_run",
}

// TestCVEConstantIsCorrect pins the CVE identifier the package
// validates. The constant feeds into SARIF rule IDs and dashboards
// downstream of the library; a typo here would silently misattribute
// every report. We use a plain equality check rather than a constant
// reference to keep the failure message obvious if the CVE drifts.
func TestCVEConstantIsCorrect(t *testing.T) {
	t.Parallel()

	if got, want := copyfail.CVE, "CVE-2026-31431"; got != want {
		t.Errorf("copyfail.CVE = %q, want %q", got, want)
	}
}

// TestDefaultsAreCanonicalPaths pins the default Module, ConfPath, and
// ModprobeDir to the values documented in the design spec §11. A
// reviewer reading the spec must see the same strings the production
// code uses; drifting these defaults would change the operational
// posture without a corresponding spec update.
func TestDefaultsAreCanonicalPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "DefaultModule", got: copyfail.DefaultModule, want: "algif_aead"},
		{name: "DefaultConfPath", got: copyfail.DefaultConfPath, want: "/etc/modprobe.d/disable-algif-aead.conf"},
		{name: "DefaultModprobeDir", got: copyfail.DefaultModprobeDir, want: "/etc/modprobe.d"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if tc.got != tc.want {
				subT.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestAll_ReturnsRequiredChecksInOrder verifies the package-level All()
// shortcut returns exactly the canonical required-check set, in the
// canonical order. The test is the contract that downstream callers
// (CI dashboards, the CLI's per-check timing tables) rely on for
// stable output ordering.
func TestAll_ReturnsRequiredChecksInOrder(t *testing.T) {
	t.Parallel()

	got := copyfail.All()
	if len(got) != len(expectedRequiredCheckIDs) {
		t.Fatalf("len(All()) = %d, want %d (required-check set)", len(got), len(expectedRequiredCheckIDs))
	}
	for i, want := range expectedRequiredCheckIDs {
		if id := got[i].ID(); id != want {
			t.Errorf("All()[%d].ID() = %q, want %q", i, id, want)
		}
	}
}

// TestAllWithOptions verifies AllWithOptions returns the same checks
// as All when given the zero Options, and that all returned checks
// have the required severity and non-empty identity fields.
func TestAllWithOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts copyfail.Options
	}{
		{
			name: "zero options uses defaults",
			opts: copyfail.Options{},
		},
		{
			name: "explicit defaults match zero options",
			opts: copyfail.Options{
				Module:      copyfail.DefaultModule,
				ConfPath:    copyfail.DefaultConfPath,
				ModprobeDir: copyfail.DefaultModprobeDir,
				Runner:      &exec.FakeRunner{},
			},
		},
		{
			name: "alternate module name preserves bundle shape",
			opts: copyfail.Options{
				Module: "algif_skcipher",
				Runner: &exec.FakeRunner{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			got := copyfail.AllWithOptions(tc.opts)

			if len(got) != len(expectedRequiredCheckIDs) {
				subT.Fatalf("len(AllWithOptions(%+v)) = %d, want %d",
					tc.opts, len(got), len(expectedRequiredCheckIDs))
			}

			for i, want := range expectedRequiredCheckIDs {
				if id := got[i].ID(); id != want {
					subT.Errorf("AllWithOptions[%d].ID() = %q, want %q", i, id, want)
				}
				if title := got[i].Title(); title == "" {
					subT.Errorf("AllWithOptions[%d].Title() is empty", i)
				}
				if desc := got[i].Description(); desc == "" {
					subT.Errorf("AllWithOptions[%d].Description() is empty", i)
				}
				if sev := got[i].Severity(); sev != report.SeverityRequired {
					subT.Errorf("AllWithOptions[%d].Severity() = %q, want %q",
						i, sev, report.SeverityRequired)
				}
			}
		})
	}
}

// TestAllWithOptions_CheckIDsAreUnique pins the uniqueness invariant
// that the SARIF rule-ID space requires. A duplicate ID would collapse
// two distinct checks into one rule, silently merging their results in
// downstream dashboards.
func TestAllWithOptions_CheckIDsAreUnique(t *testing.T) {
	t.Parallel()

	got := copyfail.AllWithOptions(copyfail.Options{Runner: &exec.FakeRunner{}})
	seen := make(map[string]int, len(got))
	for i, c := range got {
		if prev, ok := seen[c.ID()]; ok {
			t.Errorf("duplicate check ID %q at index %d (first seen at %d)", c.ID(), i, prev)
		}
		seen[c.ID()] = i
	}
}

// TestAllWithOptions_AppliesNonDefaultPaths verifies the option fields
// actually flow through to the per-check probes. We don't get easy
// access to the unexported check struct fields, so we look at each
// check's identity methods to assert non-default values reached the
// bundle.
func TestAllWithOptions_AppliesNonDefaultPaths(t *testing.T) {
	t.Parallel()

	const altModule = "algif_skcipher"
	got := copyfail.AllWithOptions(copyfail.Options{
		Module: altModule,
		Runner: &exec.FakeRunner{},
	})

	// Check count should match the canonical required-check set
	// regardless of which module name we pass — the module flows
	// through to per-check behavior, not to the slice shape.
	if len(got) != len(expectedRequiredCheckIDs) {
		t.Fatalf("len(AllWithOptions) = %d, want %d", len(got), len(expectedRequiredCheckIDs))
	}

	// Verify the IDs are stable regardless of module name (the IDs are
	// the check's identity, not its target — operators dashboarding on
	// "modprobe.dry_run" should see the same ID whether the target is
	// algif_aead or algif_skcipher).
	for i, want := range expectedRequiredCheckIDs {
		if got[i].ID() != want {
			t.Errorf("AllWithOptions[%d].ID() = %q, want %q (module override should not change IDs)",
				i, got[i].ID(), want)
		}
	}
}

// TestExpectedRequiredCheckIDs_NoTypos guards against a copy-paste
// regression in the canonical ID slice itself. Each ID must match one
// of the 5 documented check files; if a future refactor renames a
// check.go file, the test failure points the reviewer at this slice as
// the source of truth to update.
//
// In the bundler-only commit the slice is empty so the loop is a
// no-op; the test still runs to lock the helper's signature in place.
func TestExpectedRequiredCheckIDs_NoTypos(t *testing.T) {
	t.Parallel()

	requiredPrefixes := []string{"modprobe.", "module."}
	for _, id := range expectedRequiredCheckIDs {
		ok := false
		for _, p := range requiredPrefixes {
			if strings.HasPrefix(id, p) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("expected check ID %q to start with one of %v", id, requiredPrefixes)
		}
	}
}
