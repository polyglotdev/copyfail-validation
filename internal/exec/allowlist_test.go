// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"errors"
	"os/exec"
	"path/filepath"
	"testing"

	internalexec "github.com/polyglotdev/copyfail-validation/internal/exec"
)

// TestResolveCommand_AllowlistedResolves pins the happy path: an
// allowlisted command (uname, which exists on every supported dev and
// CI host) resolves to a non-empty absolute path. We do NOT assert the
// exact path because it varies by OS (/usr/bin/uname on macOS,
// /bin/uname on most Linux distros) — the contract is "resolves
// successfully and returns a usable path", not a specific path.
func TestResolveCommand_AllowlistedResolves(t *testing.T) {
	t.Parallel()
	got, err := internalexec.ResolveCommand("uname")
	if err != nil {
		t.Fatalf("ResolveCommand(uname): %v", err)
	}
	if got == "" {
		t.Errorf("ResolveCommand(uname) = %q, want non-empty path", got)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("ResolveCommand(uname) = %q, want absolute path", got)
	}
}

// TestResolveCommand_DeniedCommands pins the security gate: anything
// not in allowedCommands MUST return ErrCommandDenied — even binaries
// that obviously exist on every host (rm, ls, sh) and especially shells
// (sh, bash). A regression here would re-open arbitrary command
// execution from any caller that takes a command name from config.
func TestResolveCommand_DeniedCommands(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
	}{
		{name: "rm_is_dangerous_and_not_needed", in: "rm"},
		{name: "ls_is_unrelated_to_the_validator_scope", in: "ls"},
		{name: "sh_would_re_enable_shell_injection", in: "sh"},
		{name: "bash_would_re_enable_shell_injection", in: "bash"},
		{name: "lsof_was_intentionally_removed_per_spec_section_11", in: "lsof"},
		{name: "empty_name_is_denied_not_found", in: ""},
		{name: "absolute_path_input_is_not_a_logical_name", in: "/bin/uname"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			_, err := internalexec.ResolveCommand(tc.in)
			if !errors.Is(err, internalexec.ErrCommandDenied) {
				subT.Errorf("ResolveCommand(%q) = %v, want errors.Is(_, ErrCommandDenied)", tc.in, err)
			}
		})
	}
}

// TestResolveCommand_AllowlistedButNotInstalled exercises the fallback
// branch: an allowlisted name whose preferred absolute path does not
// exist AND whose binary is not on PATH must return ErrCommandNotFound
// (NOT ErrCommandDenied — the distinction is what the caller surfaces
// to the user).
//
// We use t.Skip when the host has the tool installed, because then the
// fallback branch is unreachable and forcing it would lie about the
// behavior. Both debsums and rpm are checked: debsums is unlikely on
// any CI host and rpm is unlikely on macOS, so at least one will
// exercise the fallback in practice.
func TestResolveCommand_AllowlistedButNotInstalled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
	}{
		{name: "debsums_uncommon_outside_debian_based_hosts", in: "debsums"},
		{name: "rpm_uncommon_on_macos_dev_hosts", in: "rpm"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if _, err := exec.LookPath(tc.in); err == nil {
				subT.Skipf("%s is installed on this host; cannot exercise the not-installed branch", tc.in)
			}
			_, err := internalexec.ResolveCommand(tc.in)
			if !errors.Is(err, internalexec.ErrCommandNotFound) {
				subT.Errorf("ResolveCommand(%q) = %v, want errors.Is(_, ErrCommandNotFound)", tc.in, err)
			}
		})
	}
}
