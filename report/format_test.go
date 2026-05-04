// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"errors"
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

// TestFormat_Constants pins the wire string for every public Format value.
// These strings are part of the JSON schema contract (spec §5) and are
// frozen at v1.0.0; this test guards against accidental rename or
// case-change refactors that would silently break downstream JSON consumers.
func TestFormat_Constants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		got  report.Format
		name string
		want string
	}{
		{name: "human", got: report.FormatHuman, want: "human"},
		{name: "json", got: report.FormatJSON, want: "json"},
		{name: "sarif", got: report.FormatSARIF, want: "sarif"},
		{name: "prometheus", got: report.FormatPrometheus, want: "prometheus"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if string(tc.got) != tc.want {
				subT.Errorf("Format string = %q, want %q", string(tc.got), tc.want)
			}
		})
	}
}

// TestParseFormat verifies the case-insensitive parser, the wrapped
// ErrUnknownFormat sentinel for unrecognized values, and the explicit
// rejection of the empty string (spec §4: ParseFormat MUST NOT silently
// default — the caller picks a default based on TTY detection, never the
// parser). Whitespace handling is deliberately strict — leading/trailing
// space is rejected, not trimmed.
func TestParseFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		wantErr error
		name    string
		in      string
		want    report.Format
	}{
		{name: "lowercase human", in: "human", want: report.FormatHuman},
		{name: "uppercase human is case-insensitive", in: "HUMAN", want: report.FormatHuman},
		{name: "mixed case sarif", in: "SaRiF", want: report.FormatSARIF},
		{name: "lowercase json", in: "json", want: report.FormatJSON},
		{name: "lowercase prometheus", in: "prometheus", want: report.FormatPrometheus},
		{name: "empty string is rejected", in: "", wantErr: report.ErrUnknownFormat},
		{name: "yaml is rejected", in: "yaml", wantErr: report.ErrUnknownFormat},
		{name: "leading whitespace is rejected", in: " json", wantErr: report.ErrUnknownFormat},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			got, err := report.ParseFormat(tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					subT.Fatalf("ParseFormat(%q) err = %v, want %v", tc.in, err, tc.wantErr)
				}
				if got != "" {
					subT.Errorf("ParseFormat(%q) = %q on error path, want zero value", tc.in, got)
				}
				return
			}
			if err != nil {
				subT.Fatalf("ParseFormat(%q) unexpected err = %v", tc.in, err)
			}
			if got != tc.want {
				subT.Errorf("ParseFormat(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
