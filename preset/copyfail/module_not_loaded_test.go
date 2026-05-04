// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/preset/copyfail"
	"github.com/polyglotdev/copyfail-validation/report"
)

// procModulesAlgifLoaded is a synthetic /proc/modules fixture where
// the target module is present. The address column is intentionally
// left as 0x0 so the fixture never embeds host-specific KASLR noise
// in the test source.
const procModulesAlgifLoaded = "algif_aead 16384 0 - Live 0x0000000000000000\n" +
	"af_alg 32768 1 algif_aead Live 0x0000000000000000\n"

// procModulesAlgifAbsent is a synthetic /proc/modules fixture with a
// few unrelated modules but NOT the target. The check should produce
// StatePass — even on a kernel with hundreds of loaded modules.
const procModulesAlgifAbsent = "ext4 753664 1 - Live 0x0000000000000000\n" +
	"crc32c_intel 16384 0 - Live 0x0000000000000000\n" +
	"nvme 53248 4 - Live 0x0000000000000000\n"

// TestModuleNotLoaded_Run pins every state the check can produce. The
// test exercises the unexported runWithSource entry point via the
// export_test helper so we can inject a t.TempDir() fixture rather than
// requiring a real /proc/modules.
//
// Coverage: pass (module absent), fail (module loaded), error (file
// missing — surfaced as "/proc not mounted"), error (parse failure on
// a malformed line).
func TestModuleNotLoaded_Run(t *testing.T) {
	t.Parallel()

	tests := []struct {
		// govet's fieldalignment pass wants the 8-byte func header
		// first, then the 16-byte strings, then the 24-byte slice
		// header LAST so the GC pointer-scan prefix stays minimal.
		setup           func(subT *testing.T) string
		name            string
		wantState       report.State
		wantErrSubstr   string
		wantDetailParts []string
	}{
		{
			name: "module absent passes",
			setup: func(subT *testing.T) string {
				return writeProcModules(subT, procModulesAlgifAbsent)
			},
			wantState:       report.StatePass,
			wantDetailParts: []string{"is not loaded", "algif_aead"},
		},
		{
			name: "module present fails with refcount detail",
			setup: func(subT *testing.T) string {
				return writeProcModules(subT, procModulesAlgifLoaded)
			},
			wantState:       report.StateFail,
			wantDetailParts: []string{"algif_aead", "currently loaded", "refcount=0"},
		},
		{
			name: "missing file errors with /proc-not-mounted detail",
			setup: func(subT *testing.T) string {
				return filepath.Join(subT.TempDir(), "nonexistent")
			},
			wantState:       report.StateError,
			wantDetailParts: []string{"/proc not mounted"},
			wantErrSubstr:   "copyfail: open",
		},
		{
			name: "malformed proc/modules errors with parse detail",
			setup: func(subT *testing.T) string {
				return writeProcModules(subT, "this line is broken\n")
			},
			wantState:       report.StateError,
			wantDetailParts: []string{"parse"},
			wantErrSubstr:   "copyfail: parse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			path := tc.setup(subT)

			runFn := copyfail.NewModuleNotLoadedCheckForTest("algif_aead", path)
			res := runFn(context.Background())

			if res.State != tc.wantState {
				subT.Fatalf("State = %q, want %q (Detail=%q, Err=%q)",
					res.State, tc.wantState, res.Detail, res.Err)
			}
			for _, want := range tc.wantDetailParts {
				if !strings.Contains(res.Detail, want) {
					subT.Errorf("Detail = %q, want substring %q", res.Detail, want)
				}
			}
			if tc.wantErrSubstr != "" && !strings.Contains(res.Err, tc.wantErrSubstr) {
				subT.Errorf("Err = %q, want substring %q", res.Err, tc.wantErrSubstr)
			}

			// Identity fields are populated on every branch, even
			// StateError. The Runner only stamps DurationMS; everything
			// else is the check's responsibility.
			if res.CheckID != "module.not_loaded" {
				subT.Errorf("CheckID = %q, want %q", res.CheckID, "module.not_loaded")
			}
			if res.Severity != report.SeverityRequired {
				subT.Errorf("Severity = %q, want %q", res.Severity, report.SeverityRequired)
			}
			if res.StartedAt.IsZero() {
				subT.Errorf("StartedAt is zero; check did not stamp it")
			}

			if res.Evidence == nil {
				subT.Fatalf("Evidence is nil")
			}
			if got, want := res.Evidence["module"], "algif_aead"; got != want {
				subT.Errorf("Evidence[module] = %v, want %v", got, want)
			}
		})
	}
}

// TestModuleNotLoaded_LoadedModuleEvidenceCarriesMatchedFields pins
// the evidence shape on the StateFail branch: the matched submap must
// expose the loaded module's name, size, refcount, and state so audit
// dashboards have enough to triage WHICH variant of the module is
// present (e.g., a kernel with two AF_ALG-family modules loaded).
func TestModuleNotLoaded_LoadedModuleEvidenceCarriesMatchedFields(t *testing.T) {
	t.Parallel()

	path := writeProcModules(t, procModulesAlgifLoaded)
	runFn := copyfail.NewModuleNotLoadedCheckForTest("algif_aead", path)
	res := runFn(context.Background())

	if res.State != report.StateFail {
		t.Fatalf("State = %q, want %q", res.State, report.StateFail)
	}

	matched, ok := res.Evidence["matched"].(map[string]any)
	if !ok {
		t.Fatalf("Evidence[matched] type = %T, want map[string]any", res.Evidence["matched"])
	}
	if got, want := matched["name"], "algif_aead"; got != want {
		t.Errorf("matched[name] = %v, want %v", got, want)
	}
	if got, want := matched["size"], int64(16384); got != want {
		t.Errorf("matched[size] = %v, want %v", got, want)
	}
	if got, want := matched["refcount"], 0; got != want {
		t.Errorf("matched[refcount] = %v, want %v", got, want)
	}
	if got, want := matched["state"], "Live"; got != want {
		t.Errorf("matched[state] = %v, want %v", got, want)
	}
	if got, want := res.Evidence["is_loaded"], true; got != want {
		t.Errorf("Evidence[is_loaded] = %v, want %v", got, want)
	}
}

// TestModuleNotLoaded_PassEvidenceIncludesTotalCount pins the
// total_modules field on the StatePass branch. The count is
// informational — operators reading the audit log can compare it
// against expected values for their kernel build.
func TestModuleNotLoaded_PassEvidenceIncludesTotalCount(t *testing.T) {
	t.Parallel()

	path := writeProcModules(t, procModulesAlgifAbsent)
	runFn := copyfail.NewModuleNotLoadedCheckForTest("algif_aead", path)
	res := runFn(context.Background())

	if res.State != report.StatePass {
		t.Fatalf("State = %q, want %q", res.State, report.StatePass)
	}
	if got, want := res.Evidence["total_modules"], 3; got != want {
		t.Errorf("Evidence[total_modules] = %v, want %v", got, want)
	}
	if got, want := res.Evidence["is_loaded"], false; got != want {
		t.Errorf("Evidence[is_loaded] = %v, want %v", got, want)
	}
}

// TestModuleNotLoaded_DefaultBundleIncludesCheck is the integration
// point with All()/AllWithOptions: the check must appear in the
// default bundle with the canonical ID, even though the production
// path reads /proc/modules (which the test cannot inject).
func TestModuleNotLoaded_DefaultBundleIncludesCheck(t *testing.T) {
	t.Parallel()

	c := findCheckByID(t, copyfail.Options{Runner: &exec.FakeRunner{}}, "module.not_loaded")
	if c.ID() != "module.not_loaded" {
		t.Errorf("ID() = %q, want %q", c.ID(), "module.not_loaded")
	}
	if c.Severity() != report.SeverityRequired {
		t.Errorf("Severity() = %q, want %q", c.Severity(), report.SeverityRequired)
	}
	if got, _ := c.Applicable(context.Background()); !got {
		t.Errorf("Applicable() = false, want true")
	}
}

// writeProcModules writes a synthetic /proc/modules fixture inside
// subT.TempDir() and returns the absolute path. Centralized so the
// per-test setup is a single line.
func writeProcModules(subT *testing.T, body string) string {
	subT.Helper()
	dir := subT.TempDir()
	path := filepath.Join(dir, "modules")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		subT.Fatalf("write fixture %q: %v", path, err)
	}
	return path
}
