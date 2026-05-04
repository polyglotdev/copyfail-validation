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

// TestModprobeDependencyChain_Run pins every state and override
// scenario the dependency-chain check can produce. The fixtures use a
// per-subtest t.TempDir() so the file-system state is hermetic; each
// dirFiles map is dropped into the temp dir as flat *.conf files.
//
// Order of evaluation matters: modprobe scans /etc/modprobe.d in
// alphabetical order with "later wins" semantics, so 99-override.conf
// shadows 00-blacklist.conf when both touch the same install
// directive. The check's purpose is to flag exactly that override
// pattern.
func TestModprobeDependencyChain_Run(t *testing.T) {
	t.Parallel()

	const module = "algif_aead"

	tests := []struct {
		// govet's fieldalignment pass wants the 8-byte map and func
		// headers first, then the 16-byte strings, then the 24-byte
		// slice header. Putting the slice LAST among pointer-bearing
		// fields minimizes the GC pointer-scan prefix.
		dirFiles        map[string]string
		setup           func(subT *testing.T) string
		name            string
		wantState       report.State
		wantDetailParts []string
	}{
		{
			name: "single canonical blocklist passes",
			dirFiles: map[string]string{
				"00-blacklist.conf": "install algif_aead /bin/false\nblacklist algif_aead\n",
			},
			wantState:       report.StatePass,
			wantDetailParts: []string{"resolves to /bin/false"},
		},
		{
			name: "later override file fails (blocklist defeated)",
			dirFiles: map[string]string{
				"00-blacklist.conf":    "install algif_aead /bin/false\nblacklist algif_aead\n",
				"99-experimental.conf": "install algif_aead /bin/true\n",
			},
			wantState:       report.StateFail,
			wantDetailParts: []string{"overridden", "99-experimental.conf"},
		},
		{
			name: "later override with modprobe wrapper fails",
			dirFiles: map[string]string{
				"00-blacklist.conf": "install algif_aead /bin/false\n",
				"99-bypass.conf":    "install algif_aead /sbin/modprobe --ignore-install algif_aead\n",
			},
			wantState:       report.StateFail,
			wantDetailParts: []string{"overridden", "99-bypass.conf"},
		},
		{
			name: "no install directive at all fails",
			dirFiles: map[string]string{
				"00-other.conf": "blacklist algif_skcipher\n",
			},
			wantState:       report.StateFail,
			wantDetailParts: []string{"no install directive", module},
		},
		{
			name: "directory missing fails",
			setup: func(subT *testing.T) string {
				return filepath.Join(subT.TempDir(), "does-not-exist")
			},
			wantState:       report.StateFail,
			wantDetailParts: []string{"directory missing"},
		},
		{
			name: "non-conf files are skipped (only baseline counts)",
			dirFiles: map[string]string{
				"00-blacklist.conf":    "install algif_aead /bin/false\n",
				"99-override.conf.bak": "install algif_aead /bin/true\n",
				"README":               "human-readable docs\n",
			},
			wantState:       report.StatePass,
			wantDetailParts: []string{"resolves to /bin/false"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			var dir string
			switch {
			case tc.setup != nil:
				dir = tc.setup(subT)
			default:
				dir = subT.TempDir()
				for name, body := range tc.dirFiles {
					path := filepath.Join(dir, name)
					if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
						subT.Fatalf("write fixture %q: %v", path, err)
					}
				}
			}

			opts := copyfail.Options{
				ModprobeDir: dir,
				Module:      module,
				Runner:      &exec.FakeRunner{},
			}
			c := findCheckByID(subT, opts, "modprobe.dependency_chain")

			res := c.Run(context.Background())

			if res.CheckID != "modprobe.dependency_chain" {
				subT.Errorf("CheckID = %q, want %q", res.CheckID, "modprobe.dependency_chain")
			}
			if res.State != tc.wantState {
				subT.Fatalf("State = %q, want %q (Detail=%q)", res.State, tc.wantState, res.Detail)
			}
			for _, want := range tc.wantDetailParts {
				if !strings.Contains(res.Detail, want) {
					subT.Errorf("Detail = %q, want substring %q", res.Detail, want)
				}
			}
			if res.Evidence == nil {
				subT.Fatalf("Evidence is nil")
			}
			if got, want := res.Evidence["dir"], dir; got != want {
				subT.Errorf("Evidence[dir] = %v, want %v", got, want)
			}
			if got, want := res.Evidence["module"], module; got != want {
				subT.Errorf("Evidence[module] = %v, want %v", got, want)
			}
		})
	}
}

// TestModprobeDependencyChain_OverrideEvidenceCarriesSourceAndTarget
// pins the spec §11 evidence shape for the override-fail branch:
// override_source must point at "<file>:<line>" so the operator can
// jump directly to the offending directive, and override_target must
// echo the resolved install command for forensic clarity.
func TestModprobeDependencyChain_OverrideEvidenceCarriesSourceAndTarget(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00-blacklist.conf"),
		[]byte("install algif_aead /bin/false\n"), 0o600); err != nil {
		t.Fatalf("write 00-blacklist.conf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "99-experimental.conf"),
		[]byte("install algif_aead /bin/true\n"), 0o600); err != nil {
		t.Fatalf("write 99-experimental.conf: %v", err)
	}

	opts := copyfail.Options{
		ModprobeDir: dir,
		Runner:      &exec.FakeRunner{},
	}
	c := findCheckByID(t, opts, "modprobe.dependency_chain")
	res := c.Run(context.Background())

	if res.State != report.StateFail {
		t.Fatalf("State = %q, want %q (Detail=%q)", res.State, report.StateFail, res.Detail)
	}

	source, ok := res.Evidence["override_source"].(string)
	if !ok {
		t.Fatalf("Evidence[override_source] type = %T, want string", res.Evidence["override_source"])
	}
	if !strings.Contains(source, "99-experimental.conf:") {
		t.Errorf("Evidence[override_source] = %q, want substring %q", source, "99-experimental.conf:")
	}

	target, ok := res.Evidence["override_target"].(string)
	if !ok {
		t.Fatalf("Evidence[override_target] type = %T, want string", res.Evidence["override_target"])
	}
	if target != "/bin/true" {
		t.Errorf("Evidence[override_target] = %q, want %q", target, "/bin/true")
	}
}

// TestModprobeDependencyChain_LastInstallEvidence pins the
// last_install_target / last_install_source fields on the StatePass
// branch — the spec §11 Evidence shape requires these regardless of
// pass/fail because operators want to confirm WHICH file produced the
// authoritative resolution, not just that the resolution was correct.
func TestModprobeDependencyChain_LastInstallEvidence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00-blacklist.conf"),
		[]byte("install algif_aead /bin/false\nblacklist algif_aead\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	opts := copyfail.Options{
		ModprobeDir: dir,
		Runner:      &exec.FakeRunner{},
	}
	c := findCheckByID(t, opts, "modprobe.dependency_chain")
	res := c.Run(context.Background())

	if res.State != report.StatePass {
		t.Fatalf("State = %q, want %q (Detail=%q)", res.State, report.StatePass, res.Detail)
	}

	if got, want := res.Evidence["last_install_target"], "/bin/false"; got != want {
		t.Errorf("Evidence[last_install_target] = %v, want %v", got, want)
	}
	source, ok := res.Evidence["last_install_source"].(string)
	if !ok {
		t.Fatalf("Evidence[last_install_source] type = %T, want string", res.Evidence["last_install_source"])
	}
	if !strings.Contains(source, "00-blacklist.conf:") {
		t.Errorf("Evidence[last_install_source] = %q, want substring %q", source, "00-blacklist.conf:")
	}
}

// TestModprobeDependencyChain_MalformedFileIsStateError pins the
// error path: a malformed conf file in the directory bubbles up as
// StateError with a wrapped error in res.Err. The operator can then
// distinguish "the chain is broken by content" (StateFail) from "we
// cannot parse one of the files" (StateError) and prioritize the
// latter as a probe failure rather than a posture failure.
func TestModprobeDependencyChain_MalformedFileIsStateError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00-broken.conf"),
		[]byte("install\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	opts := copyfail.Options{
		ModprobeDir: dir,
		Runner:      &exec.FakeRunner{},
	}
	c := findCheckByID(t, opts, "modprobe.dependency_chain")
	res := c.Run(context.Background())

	if res.State != report.StateError {
		t.Errorf("State = %q, want %q (Detail=%q, Err=%q)",
			res.State, report.StateError, res.Detail, res.Err)
	}
	if !strings.Contains(res.Err, "copyfail: scan") {
		t.Errorf("Err = %q, want substring %q", res.Err, "copyfail: scan")
	}
}

// TestModprobeDependencyChain_ApplicableAlwaysTrue pins the universal
// applicability — the check has to run even on hosts where
// /etc/modprobe.d is missing (the missing-dir case is itself an
// observable failure mode the check classifies as StateFail).
func TestModprobeDependencyChain_ApplicableAlwaysTrue(t *testing.T) {
	t.Parallel()

	c := findCheckByID(t, copyfail.Options{Runner: &exec.FakeRunner{}}, "modprobe.dependency_chain")
	got, reason := c.Applicable(context.Background())
	if !got {
		t.Errorf("Applicable() = false (reason=%q), want true", reason)
	}
	if reason != "" {
		t.Errorf("Applicable() reason = %q, want empty", reason)
	}
}
