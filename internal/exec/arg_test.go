// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"errors"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// TestArg_Validate is the central pin for the trust-boundary contract:
// Trusted always validates regardless of content, and Untrusted is held
// to the strict UntrustedArgRE + no-leading-dash rule. The test guards
// against any future loosening of the regex (which would weaken the
// shell-injection defense) and against accidental removal of the
// leading-dash check (which would re-open the flag-injection vector).
func TestArg_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wantErr error
		in      exec.Arg
		name    string
	}{
		// --- Trusted: every case must validate, including ones that
		// would be rejected for Untrusted. The whole point of Trusted
		// is to record an explicit caller assertion of safety.
		{
			name: "trusted_empty_string_passes",
			in:   exec.Trusted(""),
		},
		{
			name: "trusted_with_shell_metacharacters_passes",
			in:   exec.Trusted("anything goes; rm -rf /"),
		},
		{
			name: "trusted_path_with_traversal_passes_caller_owns_path_safety",
			in:   exec.Trusted("../../etc/shadow"),
		},
		{
			name: "trusted_leading_dash_passes_for_fixed_flag_constants",
			in:   exec.Trusted("--flag=value"),
		},
		// --- Untrusted: characters in the safe set + non-empty +
		// non-leading-dash. These mirror real values from rpm/dpkg.
		{
			name: "untrusted_kernel_module_name",
			in:   exec.Untrusted("algif_aead"),
		},
		{
			name: "untrusted_rpm_nvr_with_dots_dashes_underscores",
			in:   exec.Untrusted("util-linux-core-2.39.4-7.amzn2023.x86_64"),
		},
		{
			name: "untrusted_absolute_path",
			in:   exec.Untrusted("/usr/bin/su"),
		},
		{
			name: "untrusted_version_string",
			in:   exec.Untrusted("v1.2.3"),
		},
		{
			name: "untrusted_email_like_at_sign_and_plus",
			in:   exec.Untrusted("user+tag@example.com"),
		},
		{
			name: "untrusted_kv_with_equals_and_comma",
			in:   exec.Untrusted("k=v,a=b"),
		},
		// --- Untrusted: rejected. Each case targets a specific
		// injection vector that has bitten real systems.
		{
			name:    "untrusted_semicolon_command_chain_rejected",
			in:      exec.Untrusted("foo;rm -rf /"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_space_rejected_token_split",
			in:      exec.Untrusted("foo bar"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_dollar_var_expansion_rejected",
			in:      exec.Untrusted("foo$BAR"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_backtick_command_substitution_rejected",
			in:      exec.Untrusted("foo`whoami`"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_pipe_rejected",
			in:      exec.Untrusted("foo|cat"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_redirect_rejected",
			in:      exec.Untrusted("foo>out"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_newline_rejected",
			in:      exec.Untrusted("foo\nbar"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_nul_byte_rejected",
			in:      exec.Untrusted("foo\x00bar"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_glob_star_rejected",
			in:      exec.Untrusted("foo*"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_long_flag_rejected_flag_injection_guard",
			in:      exec.Untrusted("--config=/etc/passwd"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_short_flag_rejected_flag_injection_guard",
			in:      exec.Untrusted("-rf"),
			wantErr: exec.ErrInvalidArg,
		},
		{
			name:    "untrusted_empty_string_rejected_must_be_non_empty",
			in:      exec.Untrusted(""),
			wantErr: exec.ErrInvalidArg,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			err := exec.Validate(tc.in)
			switch {
			case tc.wantErr == nil && err != nil:
				subT.Errorf("Validate(%v) = %v, want nil", tc.in, err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				subT.Errorf("Validate(%v) = %v, want errors.Is(_, %v)", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestArg_StringReturnsUnderlyingValue is a tiny pin against accidental
// edits to the String() methods (e.g., adding quoting, lowercasing).
// Runner implementations rely on String() returning the byte-exact
// argument so the test would notice if a runtime check ever started
// mutating arg values silently.
func TestArg_StringReturnsUnderlyingValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   exec.Arg
		want string
		name string
	}{
		{name: "trusted_round_trip", in: exec.Trusted("--flag=value"), want: "--flag=value"},
		{name: "untrusted_round_trip", in: exec.Untrusted("foo"), want: "foo"},
		{name: "trusted_empty_round_trip", in: exec.Trusted(""), want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if got := tc.in.String(); got != tc.want {
				subT.Errorf("%v.String() = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
