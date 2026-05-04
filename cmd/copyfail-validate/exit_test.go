// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

// TestComputeExit_PriorityOrder asserts the exit-code priority spec in
// docs/superpowers/specs/2026-05-04-copyfail-validation-design.md §6:
// a required Fail outranks a required Error, and an all-pass Required
// bucket maps to exitOK. Each case constructs a Report with a specific
// Summary.Required shape and asserts the computed code.
func TestComputeExit_PriorityOrder(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rep  report.Report
		want int
	}{
		{
			name: "all required pass returns exitOK",
			rep: report.Report{
				Summary: report.Summary{
					Required: report.Bucket{Pass: 5, Fail: 0, Error: 0},
				},
			},
			want: exitOK,
		},
		{
			name: "single required fail returns exitMitigationGap",
			rep: report.Report{
				Summary: report.Summary{
					Required: report.Bucket{Pass: 4, Fail: 1, Error: 0},
				},
			},
			want: exitMitigationGap,
		},
		{
			name: "single required error returns exitCheckError",
			rep: report.Report{
				Summary: report.Summary{
					Required: report.Bucket{Pass: 4, Fail: 0, Error: 1},
				},
			},
			want: exitCheckError,
		},
		{
			name: "required fail wins over required error",
			rep: report.Report{
				Summary: report.Summary{
					Required: report.Bucket{Pass: 3, Fail: 1, Error: 1},
				},
			},
			want: exitMitigationGap,
		},
		{
			name: "many required fails still returns exitMitigationGap",
			rep: report.Report{
				Summary: report.Summary{
					Required: report.Bucket{Pass: 0, Fail: 5, Error: 0},
				},
			},
			want: exitMitigationGap,
		},
		{
			name: "many required errors return exitCheckError",
			rep: report.Report{
				Summary: report.Summary{
					Required: report.Bucket{Pass: 0, Fail: 0, Error: 5},
				},
			},
			want: exitCheckError,
		},
		{
			name: "empty Required bucket returns exitOK",
			rep:  report.Report{Summary: report.Summary{}},
			want: exitOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			got := computeExit(tc.rep)
			if got != tc.want {
				subT.Fatalf("computeExit() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestExitCodeConstants_FrozenValues guards the exit-code spec from
// accidental renumbering. The values are part of the v1.0.0 frozen
// contract — every alerting rule, every SSM playbook, every
// operator-facing dashboard pins on these specific integers. A
// renumbering is a major version bump, never a routine change.
func TestExitCodeConstants_FrozenValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  int
		want int
	}{
		{name: "exitOK is zero", got: exitOK, want: 0},
		{name: "exitMitigationGap is two", got: exitMitigationGap, want: 2},
		{name: "exitToolError is three", got: exitToolError, want: 3},
		{name: "exitCheckError is four", got: exitCheckError, want: 4},
		{name: "exitUsage is sixty-four", got: exitUsage, want: 64},
		{name: "exitInterrupted is one-thirty", got: exitInterrupted, want: 130},
		{name: "exitTerminated is one-forty-three", got: exitTerminated, want: 143},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if tc.got != tc.want {
				subT.Fatalf("exit code constant changed: got %d, want %d", tc.got, tc.want)
			}
		})
	}
}
