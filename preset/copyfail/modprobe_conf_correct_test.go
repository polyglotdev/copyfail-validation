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

// TestModprobeConfCorrect_Run pins every state the conf-correct check
// can produce. The fixtures cover: both directives present (pass);
// only install present (fail with "blacklist missing"); only blacklist
// present (fail with "install missing"); install with the wrong target
// (fail with both directives flagged because the install does not
// match /bin/false); missing file (fail with file-missing detail); and
// malformed conf (StateError from kernelmod.ParseConfFile).
//
// Each fail case asserts on a substring of Detail rather than the full
// message so a future copy-edit of the operator-readable text does not
// break the test.
func TestModprobeConfCorrect_Run(t *testing.T) {
	t.Parallel()

	tests := []struct {
		// govet's fieldalignment pass wants the 8-byte func header
		// first, then the 16-byte strings, then the 24-byte slice
		// header, then the 1-byte bool tail. Putting the slice LAST
		// among pointer-bearing fields shrinks the GC pointer-scan
		// prefix by 8 bytes.
		setup           func(subT *testing.T) string
		name            string
		wantState       report.State
		wantInstall     string
		wantDetailParts []string
		wantBlacklist   bool
	}{
		{
			name: "both directives present passes",
			setup: func(subT *testing.T) string {
				return writeConf(subT, "install algif_aead /bin/false\nblacklist algif_aead\n")
			},
			wantState:     report.StatePass,
			wantInstall:   "/bin/false",
			wantBlacklist: true,
		},
		{
			name: "only install directive fails (blacklist missing)",
			setup: func(subT *testing.T) string {
				return writeConf(subT, "install algif_aead /bin/false\n")
			},
			wantState:       report.StateFail,
			wantDetailParts: []string{"blacklist algif_aead"},
			wantInstall:     "/bin/false",
			wantBlacklist:   false,
		},
		{
			name: "only blacklist directive fails (install missing)",
			setup: func(subT *testing.T) string {
				return writeConf(subT, "blacklist algif_aead\n")
			},
			wantState:       report.StateFail,
			wantDetailParts: []string{"install algif_aead /bin/false"},
			wantInstall:     "",
			wantBlacklist:   true,
		},
		{
			name: "wrong install target fails (must be /bin/false)",
			setup: func(subT *testing.T) string {
				return writeConf(subT, "install algif_aead /bin/true\nblacklist algif_aead\n")
			},
			wantState:       report.StateFail,
			wantDetailParts: []string{"install algif_aead /bin/false"},
			wantInstall:     "/bin/true",
			wantBlacklist:   true,
		},
		{
			name: "file missing fails with explicit detail",
			setup: func(subT *testing.T) string {
				return filepath.Join(subT.TempDir(), "absent.conf")
			},
			wantState:       report.StateFail,
			wantDetailParts: []string{"does not exist"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			path := tc.setup(subT)
			opts := copyfail.Options{ConfPath: path, Runner: &exec.FakeRunner{}}
			c := findCheckByID(subT, opts, "modprobe.conf_correct")

			res := c.Run(context.Background())

			if res.CheckID != "modprobe.conf_correct" {
				subT.Errorf("CheckID = %q, want %q", res.CheckID, "modprobe.conf_correct")
			}
			if res.State != tc.wantState {
				subT.Fatalf("State = %q, want %q (Detail=%q)", res.State, tc.wantState, res.Detail)
			}
			if res.Detail == "" {
				subT.Errorf("Detail is empty; want operator-readable summary")
			}
			for _, want := range tc.wantDetailParts {
				if !strings.Contains(res.Detail, want) {
					subT.Errorf("Detail = %q, want substring %q", res.Detail, want)
				}
			}
			if res.Evidence == nil {
				subT.Fatalf("Evidence is nil")
			}
			if got, want := res.Evidence["path"], path; got != want {
				subT.Errorf("Evidence[path] = %v, want %v", got, want)
			}
			if got, want := res.Evidence["module"], "algif_aead"; got != want {
				subT.Errorf("Evidence[module] = %v, want %v", got, want)
			}

			// Pass branches must surface install_target / blacklisted
			// for downstream dashboards. Fail branches that came from
			// a parsed file should also surface them; the file-missing
			// branch deliberately omits them (no parse occurred).
			if tc.wantState == report.StatePass {
				if got, want := res.Evidence["install_target"], tc.wantInstall; got != want {
					subT.Errorf("Evidence[install_target] = %v, want %v", got, want)
				}
				if got, want := res.Evidence["blacklisted"], tc.wantBlacklist; got != want {
					subT.Errorf("Evidence[blacklisted] = %v, want %v", got, want)
				}
			}
		})
	}
}

// TestModprobeConfCorrect_MalformedFileIsStateError pins the error
// path: a conf file with a directive too short to parse (e.g.,
// "install" alone with no module argument) bubbles up as StateError
// with the kernelmod-wrapped error in res.Err. Operators can then
// distinguish "the file is wrong" (StateFail) from "we cannot tell"
// (StateError) and prioritize the latter as a probe failure rather
// than a posture failure.
func TestModprobeConfCorrect_MalformedFileIsStateError(t *testing.T) {
	t.Parallel()

	// One-token directive line: parser requires at least 2 tokens.
	path := writeConf(t, "install\n")
	opts := copyfail.Options{ConfPath: path, Runner: &exec.FakeRunner{}}
	c := findCheckByID(t, opts, "modprobe.conf_correct")

	res := c.Run(context.Background())

	if res.State != report.StateError {
		t.Errorf("State = %q, want %q (Detail=%q, Err=%q)",
			res.State, report.StateError, res.Detail, res.Err)
	}
	if res.Err == "" {
		t.Errorf("Err is empty on StateError; want wrapped parse failure")
	}
	if !strings.Contains(res.Err, "copyfail: parse") {
		t.Errorf("Err = %q, want substring %q", res.Err, "copyfail: parse")
	}
}

// TestModprobeConfCorrect_AlternateModuleName pins the Module
// flow-through: when AllWithOptions receives a non-default module
// name, the conf-correct check probes for THAT name's directives, not
// the default's. A regression here would cause the check to pass on a
// host that blocks algif_aead but leaves algif_skcipher loadable.
func TestModprobeConfCorrect_AlternateModuleName(t *testing.T) {
	t.Parallel()

	// Conf has directives for algif_skcipher only; querying for
	// algif_aead (the default) must FAIL, querying for algif_skcipher
	// (the override) must PASS.
	path := writeConf(t, "install algif_skcipher /bin/false\nblacklist algif_skcipher\n")

	defaultOpts := copyfail.Options{ConfPath: path, Runner: &exec.FakeRunner{}}
	c := findCheckByID(t, defaultOpts, "modprobe.conf_correct")
	if got := c.Run(context.Background()).State; got != report.StateFail {
		t.Errorf("default-module Run().State = %q, want %q", got, report.StateFail)
	}

	overrideOpts := copyfail.Options{
		ConfPath: path,
		Module:   "algif_skcipher",
		Runner:   &exec.FakeRunner{},
	}
	c = findCheckByID(t, overrideOpts, "modprobe.conf_correct")
	if got := c.Run(context.Background()).State; got != report.StatePass {
		t.Errorf("override-module Run().State = %q, want %q", got, report.StatePass)
	}
}

// writeConf is a per-package test helper that drops `body` into a file
// inside subT.TempDir() and returns the absolute path. Centralized so
// the per-test-case setup boilerplate stays a single line.
func writeConf(subT *testing.T, body string) string {
	subT.Helper()
	dir := subT.TempDir()
	path := filepath.Join(dir, "disable-algif-aead.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		subT.Fatalf("write fixture %q: %v", path, err)
	}
	return path
}
