// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/preset/copyfail"
	"github.com/polyglotdev/copyfail-validation/report"
)

// TestModprobeDryRun_Run pins every state the dry-run check can
// produce. The fixtures are all driven by an exec.FakeRunner returning
// canned modprobe output: the canonical "install /bin/false" line for
// pass; an alternate insmod line for fail; an empty-output / unknown
// module case for fail-with-no-output; and the various exec sentinel
// errors for StateError.
//
// The check populates res.Evidence with raw_output, resolved_to, and
// blocked on every branch — even StateError — because operator audits
// need the modprobe diagnostic regardless of whether the wrapper
// classified the error.
func TestModprobeDryRun_Run(t *testing.T) {
	t.Parallel()

	const module = "algif_aead"
	const cmdKey = "modprobe -n -v " + module

	tests := []struct {
		responses        map[string]exec.Result
		errors           map[string]error
		name             string
		wantDetailPart   string
		wantResolvedTo   string
		wantState        report.State
		wantBlocked      bool
		wantHasResolved  bool
		wantHasRawOutput bool
	}{
		{
			name: "blocked install /bin/false passes",
			responses: map[string]exec.Result{
				cmdKey: {Stdout: []byte("install /bin/false \n")},
			},
			wantState:        report.StatePass,
			wantBlocked:      true,
			wantResolvedTo:   "install /bin/false",
			wantHasResolved:  true,
			wantHasRawOutput: true,
			wantDetailPart:   "install /bin/false",
		},
		{
			name: "loadable insmod line fails",
			responses: map[string]exec.Result{
				cmdKey: {Stdout: []byte("insmod /lib/modules/6.1/kernel/crypto/algif_aead.ko\n")},
			},
			wantState:        report.StateFail,
			wantBlocked:      false,
			wantResolvedTo:   "insmod /lib/modules/6.1/kernel/crypto/algif_aead.ko",
			wantHasResolved:  true,
			wantHasRawOutput: true,
			wantDetailPart:   "insmod /lib/modules",
		},
		{
			name: "alternate install target fails",
			responses: map[string]exec.Result{
				cmdKey: {Stdout: []byte("install /bin/true\n")},
			},
			wantState:        report.StateFail,
			wantBlocked:      false,
			wantResolvedTo:   "install /bin/true",
			wantHasResolved:  true,
			wantHasRawOutput: true,
			wantDetailPart:   "install /bin/true",
		},
		{
			name: "empty output fails with explicit no-output detail",
			responses: map[string]exec.Result{
				cmdKey: {Stdout: []byte("")},
			},
			wantState:        report.StateFail,
			wantBlocked:      false,
			wantResolvedTo:   "",
			wantHasResolved:  true,
			wantHasRawOutput: true,
			wantDetailPart:   "no output",
		},
		{
			name: "command not found errors with binary-not-installed detail",
			errors: map[string]error{
				cmdKey: exec.ErrCommandNotFound,
			},
			wantState:        report.StateError,
			wantHasResolved:  true,
			wantHasRawOutput: true,
			wantDetailPart:   "modprobe binary not available",
		},
		{
			name: "command denied errors with allowlist detail",
			errors: map[string]error{
				cmdKey: exec.ErrCommandDenied,
			},
			wantState:        report.StateError,
			wantHasResolved:  true,
			wantHasRawOutput: true,
			wantDetailPart:   "allowlist",
		},
		{
			name: "timeout errors with timeout detail",
			errors: map[string]error{
				cmdKey: exec.ErrTimeout,
			},
			wantState:        report.StateError,
			wantHasResolved:  true,
			wantHasRawOutput: true,
			wantDetailPart:   "timed out",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			runner := &exec.FakeRunner{
				Responses: tc.responses,
				Errors:    tc.errors,
			}
			opts := copyfail.Options{Module: module, Runner: runner}
			c := findCheckByID(subT, opts, "modprobe.dry_run")

			res := c.Run(context.Background())

			if res.CheckID != "modprobe.dry_run" {
				subT.Errorf("CheckID = %q, want %q", res.CheckID, "modprobe.dry_run")
			}
			if res.State != tc.wantState {
				subT.Fatalf("State = %q, want %q (Detail=%q, Err=%q)",
					res.State, tc.wantState, res.Detail, res.Err)
			}
			if !strings.Contains(res.Detail, tc.wantDetailPart) {
				subT.Errorf("Detail = %q, want substring %q", res.Detail, tc.wantDetailPart)
			}
			if res.Evidence == nil {
				subT.Fatalf("Evidence is nil")
			}
			if got, want := res.Evidence["command"], "modprobe -n -v "+module; got != want {
				subT.Errorf("Evidence[command] = %v, want %v", got, want)
			}
			if got, want := res.Evidence["module"], module; got != want {
				subT.Errorf("Evidence[module] = %v, want %v", got, want)
			}
			if tc.wantHasResolved {
				if got, want := res.Evidence["resolved_to"], tc.wantResolvedTo; got != want {
					subT.Errorf("Evidence[resolved_to] = %v, want %v", got, want)
				}
			}
			if got, want := res.Evidence["blocked"], tc.wantBlocked; got != want {
				subT.Errorf("Evidence[blocked] = %v, want %v", got, want)
			}

			if tc.wantState == report.StateError && res.Err == "" {
				subT.Errorf("Err is empty on StateError; want wrapped error")
			}
		})
	}
}

// TestModprobeDryRun_RecordsExactCommandShape pins the runner-call
// shape: the underlying FakeRunner must observe ONE call with
// Name="modprobe", Args=[Trusted("-n"), Trusted("-v"), Untrusted(module)].
// This is the security-critical assertion that mirrors the analogous
// test in internal/kernelmod — a check-layer regression that re-types
// the module argument as Trusted would silently bypass the
// shell-injection guard and is the kind of regression we want a build
// failure for, not a quiet posture flip.
func TestModprobeDryRun_RecordsExactCommandShape(t *testing.T) {
	t.Parallel()

	const module = "algif_aead"
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"modprobe -n -v " + module: {Stdout: []byte("install /bin/false\n")},
		},
	}
	opts := copyfail.Options{Module: module, Runner: runner}
	c := findCheckByID(t, opts, "modprobe.dry_run")

	_ = c.Run(context.Background())

	if got, want := len(runner.Calls), 1; got != want {
		t.Fatalf("len(runner.Calls) = %d, want %d", got, want)
	}
	call := runner.Calls[0]
	if call.Name != "modprobe" {
		t.Errorf("call.Name = %q, want %q", call.Name, "modprobe")
	}
	if got, want := len(call.Args), 3; got != want {
		t.Fatalf("len(call.Args) = %d, want %d", got, want)
	}

	// Type assertions are deliberately strict: a future refactor that
	// silently re-types Untrusted to Trusted would change the security
	// contract without changing the FakeRunner stdout key, so we must
	// assert at the type level.
	if _, ok := call.Args[0].(exec.Trusted); !ok {
		t.Errorf("call.Args[0] type = %T, want exec.Trusted", call.Args[0])
	}
	if _, ok := call.Args[1].(exec.Trusted); !ok {
		t.Errorf("call.Args[1] type = %T, want exec.Trusted", call.Args[1])
	}
	mod, ok := call.Args[2].(exec.Untrusted)
	if !ok {
		t.Errorf("call.Args[2] type = %T, want exec.Untrusted", call.Args[2])
	}
	if string(mod) != module {
		t.Errorf("call.Args[2] = %q, want %q", mod, module)
	}
}

// TestModprobeDryRun_InvalidArgIsStateError pins the
// argument-validation rejection path: when the configured module name
// fails the kernelmod-layer Untrusted validator (e.g., contains a
// shell metacharacter or starts with '-'), the check produces a
// StateError that wraps exec.ErrInvalidArg. The runner records ZERO
// calls — the rejection short-circuits before the subprocess runs.
func TestModprobeDryRun_InvalidArgIsStateError(t *testing.T) {
	t.Parallel()

	runner := &exec.FakeRunner{}
	opts := copyfail.Options{Module: "algif_aead;rm -rf /", Runner: runner}
	c := findCheckByID(t, opts, "modprobe.dry_run")

	res := c.Run(context.Background())

	if res.State != report.StateError {
		t.Fatalf("State = %q, want %q (Detail=%q)",
			res.State, report.StateError, res.Detail)
	}
	if !strings.Contains(res.Detail, "rejected by argument validator") {
		t.Errorf("Detail = %q, want substring %q",
			res.Detail, "rejected by argument validator")
	}
	if got := len(runner.Calls); got != 0 {
		t.Errorf("len(runner.Calls) = %d, want 0 (validation must short-circuit)", got)
	}
}

// TestModprobeDryRun_ApplicableAlwaysTrue pins that the check does
// not skip when modprobe is missing — operators expect a StateError
// so the absence is loud and obvious.
func TestModprobeDryRun_ApplicableAlwaysTrue(t *testing.T) {
	t.Parallel()

	c := findCheckByID(t, copyfail.Options{Runner: &exec.FakeRunner{}}, "modprobe.dry_run")
	got, reason := c.Applicable(context.Background())
	if !got {
		t.Errorf("Applicable() = false (reason=%q), want true", reason)
	}
	if reason != "" {
		t.Errorf("Applicable() reason = %q, want empty", reason)
	}
}

// TestModprobeDryRun_GenericRunnerErrorWrappedInErr pins the wrapping
// contract for non-sentinel runner errors: the result's Err field
// preserves the original error (errors.Is succeeds) AND the operator
// gets an actionable Detail string.
func TestModprobeDryRun_GenericRunnerErrorWrappedInErr(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("copyfail-test: modprobe simulated failure")
	runner := &exec.FakeRunner{
		Errors: map[string]error{
			"modprobe -n -v algif_aead": wantErr,
		},
	}
	opts := copyfail.Options{Runner: runner}
	c := findCheckByID(t, opts, "modprobe.dry_run")

	res := c.Run(context.Background())

	if res.State != report.StateError {
		t.Fatalf("State = %q, want %q", res.State, report.StateError)
	}
	if !strings.Contains(res.Err, wantErr.Error()) {
		t.Errorf("Err = %q, want substring %q", res.Err, wantErr.Error())
	}
}
