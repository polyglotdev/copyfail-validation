// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/polyglotdev/copyfail-validation/check"
	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/preset/copyfail"
	"github.com/polyglotdev/copyfail-validation/report"
)

// findCheckByID returns the first check from copyfail.AllWithOptions
// matching id. Centralized so each per-check test is a single line of
// "find then run" rather than a hand-rolled loop in every TestXyz_*.
// On miss the helper fails the subtest via t.Fatalf — callers can
// safely dereference the returned value because no return path
// produces (true, nil).
//
// NOTE: this helper is shared across the per-check tests in this
// package; defining it once here eliminates duplicated lookup logic
// in every TestXyz_* file.
func findCheckByID(t *testing.T, opts copyfail.Options, id string) check.Check {
	t.Helper()
	for _, candidate := range copyfail.AllWithOptions(opts) {
		if candidate.ID() == id {
			return candidate
		}
	}
	t.Fatalf("check %q not present in copyfail.AllWithOptions(%+v)", id, opts)
	return nil
}

// TestModprobeConfPresent_Run pins every state the conf-present check
// can produce: pass on a real regular file, fail on a missing file,
// fail on a directory at the conf path (a common deployment-bug
// failure mode where the operator created a directory of fragments
// instead of a single file), and the expected Evidence shape for
// each case. The test uses t.TempDir so the file-system state is
// hermetic — no /etc edits required.
func TestModprobeConfPresent_Run(t *testing.T) {
	t.Parallel()

	tests := []struct {
		// govet's fieldalignment pass wants the 16-byte interface
		// (wantEvidVal) ahead of the func and the 16-byte strings; the
		// remaining string-aliased report.State sits at the tail.
		wantEvidVal any
		setup       func(subT *testing.T) (path string)
		wantEvidKey string
		name        string
		wantState   report.State
	}{
		{
			name: "regular file passes",
			setup: func(subT *testing.T) string {
				dir := subT.TempDir()
				path := filepath.Join(dir, "disable-algif-aead.conf")
				if err := os.WriteFile(path, []byte("install algif_aead /bin/false\nblacklist algif_aead\n"), 0o600); err != nil {
					subT.Fatalf("write fixture: %v", err)
				}
				return path
			},
			wantState:   report.StatePass,
			wantEvidKey: "is_regular",
			wantEvidVal: true,
		},
		{
			name: "missing file fails",
			setup: func(subT *testing.T) string {
				return filepath.Join(subT.TempDir(), "does-not-exist.conf")
			},
			wantState:   report.StateFail,
			wantEvidKey: "exists",
			wantEvidVal: false,
		},
		{
			name: "directory at path fails (not a regular file)",
			setup: func(subT *testing.T) string {
				dir := subT.TempDir()
				path := filepath.Join(dir, "conf-as-directory")
				if err := os.Mkdir(path, 0o700); err != nil {
					subT.Fatalf("mkdir fixture: %v", err)
				}
				return path
			},
			wantState:   report.StateFail,
			wantEvidKey: "is_regular",
			wantEvidVal: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			path := tc.setup(subT)
			opts := copyfail.Options{ConfPath: path, Runner: &exec.FakeRunner{}}

			c := findCheckByID(subT, opts, "modprobe.conf_present")

			res := c.Run(context.Background())

			if res.CheckID != "modprobe.conf_present" {
				subT.Errorf("CheckID = %q, want %q", res.CheckID, "modprobe.conf_present")
			}
			if res.Severity != report.SeverityRequired {
				subT.Errorf("Severity = %q, want %q", res.Severity, report.SeverityRequired)
			}
			if res.StartedAt.IsZero() {
				subT.Errorf("StartedAt is zero; check did not stamp it")
			}
			if res.State != tc.wantState {
				subT.Errorf("State = %q, want %q (Detail=%q)", res.State, tc.wantState, res.Detail)
			}
			if res.Detail == "" {
				subT.Errorf("Detail is empty; want operator-readable summary")
			}
			if res.Evidence == nil {
				subT.Fatalf("Evidence is nil; want path/exists at minimum")
			}
			if got, want := res.Evidence["path"], path; got != want {
				subT.Errorf("Evidence[path] = %v, want %v", got, want)
			}
			if got := res.Evidence[tc.wantEvidKey]; got != tc.wantEvidVal {
				subT.Errorf("Evidence[%q] = %v, want %v", tc.wantEvidKey, got, tc.wantEvidVal)
			}
		})
	}
}

// TestModprobeConfPresent_ApplicableAlwaysTrue pins the universal
// applicability of the check. The conf file's presence must be probed
// on every host, including ones without modprobe installed (the file
// is a configuration baseline, not a runtime artifact).
func TestModprobeConfPresent_ApplicableAlwaysTrue(t *testing.T) {
	t.Parallel()

	c := findCheckByID(t, copyfail.Options{Runner: &exec.FakeRunner{}}, "modprobe.conf_present")
	got, reason := c.Applicable(context.Background())
	if !got {
		t.Errorf("Applicable() = false (reason=%q), want true", reason)
	}
	if reason != "" {
		t.Errorf("Applicable() reason = %q, want empty string", reason)
	}
}

// TestModprobeConfPresent_RegularFileEvidenceIncludesSize pins the
// size_bytes field on the StatePass branch — the field exists so audit
// dashboards can correlate "file is suspiciously small" with other
// signals; the field is the spec §11 Evidence shape for the check.
func TestModprobeConfPresent_RegularFileEvidenceIncludesSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "disable-algif-aead.conf")
	body := []byte("install algif_aead /bin/false\nblacklist algif_aead\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	opts := copyfail.Options{ConfPath: path, Runner: &exec.FakeRunner{}}
	c := findCheckByID(t, opts, "modprobe.conf_present")

	res := c.Run(context.Background())
	if res.State != report.StatePass {
		t.Fatalf("State = %q, want pass", res.State)
	}

	got, ok := res.Evidence["size_bytes"].(int64)
	if !ok {
		t.Fatalf("Evidence[size_bytes] type = %T, want int64", res.Evidence["size_bytes"])
	}
	if got != int64(len(body)) {
		t.Errorf("Evidence[size_bytes] = %d, want %d", got, len(body))
	}
}
