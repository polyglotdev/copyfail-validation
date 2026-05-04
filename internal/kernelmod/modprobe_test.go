// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package kernelmod_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/internal/kernelmod"
)

// TestDryRunModule_ParsesOutput pins the canonical parse contract for
// `modprobe -n -v` output: ResolvedTo is the FIRST non-blank line with
// edge whitespace trimmed, RawOutput is the verbatim stdout, and
// Blocked is true iff ResolvedTo equals exactly "install /bin/false".
//
// This single table exercises every shape of legitimate modprobe
// verbose output the spec §11 modprobe.dry_run check has to handle:
// blocked module, loadable module, multi-line dependency chain,
// silent (empty) output, and leading-blank-line tolerance. A
// regression in any of these shapes would either (a) miss a real
// block, or (b) flag a loadable module as blocked — both are
// false-finding security failures, not just cosmetic bugs.
func TestDryRunModule_ParsesOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		stdout       string
		wantResolved string
		wantRaw      string
		wantBlocked  bool
	}{
		{
			name:         "blocked module emits install /bin/false (with trailing space)",
			stdout:       "install /bin/false \n",
			wantResolved: "install /bin/false",
			wantRaw:      "install /bin/false \n",
			wantBlocked:  true,
		},
		{
			name:         "loadable module emits an insmod line",
			stdout:       "insmod /lib/modules/6.1.0-amzn2023/kernel/crypto/algif_aead.ko \n",
			wantResolved: "insmod /lib/modules/6.1.0-amzn2023/kernel/crypto/algif_aead.ko",
			wantRaw:      "insmod /lib/modules/6.1.0-amzn2023/kernel/crypto/algif_aead.ko \n",
			wantBlocked:  false,
		},
		{
			name:         "multi-line dependency chain returns first line",
			stdout:       "insmod /lib/modules/6.1.0/kernel/crypto/af_alg.ko \ninsmod /lib/modules/6.1.0/kernel/crypto/algif_aead.ko \n",
			wantResolved: "insmod /lib/modules/6.1.0/kernel/crypto/af_alg.ko",
			wantRaw:      "insmod /lib/modules/6.1.0/kernel/crypto/af_alg.ko \ninsmod /lib/modules/6.1.0/kernel/crypto/algif_aead.ko \n",
			wantBlocked:  false,
		},
		{
			name:         "empty output yields zero ResolvedTo and not blocked",
			stdout:       "",
			wantResolved: "",
			wantRaw:      "",
			wantBlocked:  false,
		},
		{
			name:         "leading blank lines are skipped; first non-blank wins",
			stdout:       "\n\n   \ninstall /bin/false \n",
			wantResolved: "install /bin/false",
			wantRaw:      "\n\n   \ninstall /bin/false \n",
			wantBlocked:  true,
		},
		{
			name:         "alternate install target (e.g. /bin/true) is NOT blocked",
			stdout:       "install /bin/true \n",
			wantResolved: "install /bin/true",
			wantRaw:      "install /bin/true \n",
			wantBlocked:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			runner := &exec.FakeRunner{
				Responses: map[string]exec.Result{
					"modprobe -n -v algif_aead": {
						Stdout:   []byte(tc.stdout),
						ExitCode: 0,
					},
				},
			}

			got, err := kernelmod.DryRunModule(context.Background(), runner, "algif_aead")
			if err != nil {
				subT.Fatalf("DryRunModule() unexpected error: %v", err)
			}

			want := kernelmod.DryRun{
				ResolvedTo: tc.wantResolved,
				RawOutput:  tc.wantRaw,
				Blocked:    tc.wantBlocked,
			}
			if diff := cmp.Diff(want, got); diff != "" {
				subT.Errorf("DryRunModule() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDryRunModule_RecordsCommandShape pins the EXACT subprocess
// invocation shape produced by DryRunModule: the command name is
// "modprobe", the first two args are Trusted("-n") and Trusted("-v")
// (constants — bypass character validation), and the third is the
// caller-supplied module name wrapped as Untrusted (which the
// internal/exec layer will validate before the subprocess starts).
//
// This is a CRITICAL security regression test. If a future refactor
// silently re-types the module argument as Trusted, the
// Untrusted-input character validation (UntrustedArgRE +
// flag-injection guard) would be bypassed, re-opening the
// shell-injection class of vulnerability that internal/exec was
// built to close. We assert on the concrete TYPES via type
// assertions — string equality is not enough because
// Trusted("algif_aead") and Untrusted("algif_aead") have identical
// String() output but diametrically opposite security guarantees.
func TestDryRunModule_RecordsCommandShape(t *testing.T) {
	t.Parallel()

	const module = "algif_aead"
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"modprobe -n -v " + module: {Stdout: []byte("install /bin/false \n"), ExitCode: 0},
		},
	}

	if _, err := kernelmod.DryRunModule(context.Background(), runner, module); err != nil {
		t.Fatalf("DryRunModule() error: %v", err)
	}

	if got, want := len(runner.Calls), 1; got != want {
		t.Fatalf("len(runner.Calls) = %d, want %d", got, want)
	}

	call := runner.Calls[0]
	if got, want := call.Name, "modprobe"; got != want {
		t.Errorf("call.Name = %q, want %q", got, want)
	}
	if got, want := len(call.Args), 3; got != want {
		t.Fatalf("len(call.Args) = %d, want %d", got, want)
	}

	// Arg 0: Trusted("-n"). Type assertion fails iff a future change
	// retypes the flag — this would not change the Stdout key but
	// would silently change the security contract for callers that
	// inspect Cmd.Args at higher layers.
	flagN, ok := call.Args[0].(exec.Trusted)
	if !ok {
		t.Errorf("call.Args[0] type = %T, want exec.Trusted", call.Args[0])
	}
	if string(flagN) != "-n" {
		t.Errorf("call.Args[0] = %q, want %q", flagN, "-n")
	}

	// Arg 1: Trusted("-v"). Same rationale as Arg 0.
	flagV, ok := call.Args[1].(exec.Trusted)
	if !ok {
		t.Errorf("call.Args[1] type = %T, want exec.Trusted", call.Args[1])
	}
	if string(flagV) != "-v" {
		t.Errorf("call.Args[1] = %q, want %q", flagV, "-v")
	}

	// Arg 2: Untrusted(module). This is the critical assertion — if
	// a refactor re-typed this as Trusted to "skip validation", the
	// shell-injection guard (UntrustedArgRE) would be bypassed.
	mod, ok := call.Args[2].(exec.Untrusted)
	if !ok {
		t.Errorf("call.Args[2] type = %T, want exec.Untrusted", call.Args[2])
	}
	if string(mod) != module {
		t.Errorf("call.Args[2] = %q, want %q", mod, module)
	}
}

// TestDryRunModule_RejectsArgumentInjection pins the
// shell-metacharacter-injection guard. The internal/exec validator
// rejects any Untrusted argument containing characters outside
// UntrustedArgRE — this includes ';', the shell command separator
// that historically allowed `modprobe -nv "algif_aead;rm -rf /"` to
// chain arbitrary commands when the wrapper used `sh -c`.
//
// Even though internal/exec runs commands directly via os/exec (no
// shell), the validator stays as defense-in-depth: a future regression
// that adds a shell-execution path would still hit this guard. This
// test guarantees the guard fires at the kernelmod layer BEFORE the
// Runner is even invoked, by asserting the FakeRunner records ZERO
// calls. Without the kernelmod-layer Validate, the FakeRunner (which
// does NOT validate, by design — it's a recorder) would happily
// register the malicious cmd into Calls, breaking the contract that
// invalid args never reach the runner.
func TestDryRunModule_RejectsArgumentInjection(t *testing.T) {
	t.Parallel()

	runner := &exec.FakeRunner{}
	_, err := kernelmod.DryRunModule(context.Background(), runner, "algif_aead;rm -rf /")
	if !errors.Is(err, exec.ErrInvalidArg) {
		t.Fatalf("DryRunModule() error = %v, want errors.Is(_, exec.ErrInvalidArg)", err)
	}
	if got := len(runner.Calls); got != 0 {
		t.Errorf("len(runner.Calls) = %d, want 0 (validation must short-circuit BEFORE runner.Run)", got)
	}
}

// TestDryRunModule_RejectsLeadingDash pins the flag-injection guard.
// A module name like "-rf" would be interpreted by modprobe as the
// "-r -f" combined short-flag form (--remove --force) instead of as
// the positional module argument, which would silently REMOVE
// modules instead of dry-running them. The internal/exec validator
// rejects any Untrusted value starting with '-' for exactly this
// reason. This test pins the guard at the kernelmod boundary so a
// future refactor cannot accidentally drop the protection by, e.g.,
// changing the module wrapping to Trusted. As with the metacharacter
// test, the FakeRunner must record ZERO calls — the rejection must
// short-circuit before runner.Run is ever invoked.
func TestDryRunModule_RejectsLeadingDash(t *testing.T) {
	t.Parallel()

	runner := &exec.FakeRunner{}
	_, err := kernelmod.DryRunModule(context.Background(), runner, "-rf")
	if !errors.Is(err, exec.ErrInvalidArg) {
		t.Fatalf("DryRunModule() error = %v, want errors.Is(_, exec.ErrInvalidArg)", err)
	}
	if got := len(runner.Calls); got != 0 {
		t.Errorf("len(runner.Calls) = %d, want 0 (validation must short-circuit BEFORE runner.Run)", got)
	}
}

// TestDryRunModule_PropagatesTimeoutError pins the error-propagation
// contract for exec.ErrTimeout: when the underlying Runner reports a
// timeout, DryRunModule must wrap (not swallow) the sentinel so
// callers using errors.Is can distinguish a timeout from other
// failures (the modprobe.dry_run check writes a different evidence
// blob for timeouts vs parse failures vs allowlist denials).
func TestDryRunModule_PropagatesTimeoutError(t *testing.T) {
	t.Parallel()

	runner := &exec.FakeRunner{
		Errors: map[string]error{
			"modprobe -n -v algif_aead": exec.ErrTimeout,
		},
	}

	_, err := kernelmod.DryRunModule(context.Background(), runner, "algif_aead")
	if !errors.Is(err, exec.ErrTimeout) {
		t.Fatalf("DryRunModule() error = %v, want errors.Is(_, exec.ErrTimeout)", err)
	}
}

// TestDryRunModule_WrapsGenericRunnerError pins the wrapping
// contract for non-sentinel runner errors: the returned error must
// preserve the underlying error via %w so errors.Is on the original
// sentinel still works AND must include the kernelmod context
// ("kernelmod: modprobe -n -v <module>") so audit logs identify the
// failing operation. Without the prefix, a generic exec error would
// be ambiguous between the dozens of subprocess invocations in a
// full validation run.
func TestDryRunModule_WrapsGenericRunnerError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("kernelmod-test: modprobe simulated failure")
	runner := &exec.FakeRunner{
		Errors: map[string]error{
			"modprobe -n -v algif_aead": wantErr,
		},
	}

	_, err := kernelmod.DryRunModule(context.Background(), runner, "algif_aead")
	if !errors.Is(err, wantErr) {
		t.Fatalf("DryRunModule() error = %v, want errors.Is(_, %v)", err, wantErr)
	}

	// Assert the kernelmod context prefix is present so callers
	// reading logs can identify the failing operation. We use
	// strings.Contains rather than HasPrefix because errors.Is
	// wrapping may add additional context before the prefix in
	// future refactors — substring is the least-fragile match
	// for the human-readable audit-log shape.
	const wantPrefix = "kernelmod: modprobe -n -v algif_aead"
	if got := err.Error(); !strings.Contains(got, wantPrefix) {
		t.Errorf("error message = %q, want substring %q", got, wantPrefix)
	}
}

// TestDryRunModule_PartialResultOnNonzeroExit pins the
// partial-output contract: when modprobe both prints useful verbose
// output AND exits non-zero, callers must receive both the parsed
// DryRun (so they can log the evidence) AND the error (so they can
// classify the failure). Without this, a bug where modprobe -n -v
// resolves to "install /bin/false" but exits 1 would either lose
// the block evidence (if we returned only on success) or hide the
// exit-code signal (if we returned only the DryRun). This test pins
// both halves of the contract simultaneously.
func TestDryRunModule_PartialResultOnNonzeroExit(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("kernelmod-test: modprobe exited 1")
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"modprobe -n -v algif_aead": {
				Stdout:   []byte("install /bin/false \n"),
				ExitCode: 1,
			},
		},
		Errors: map[string]error{
			"modprobe -n -v algif_aead": wantErr,
		},
	}

	got, err := kernelmod.DryRunModule(context.Background(), runner, "algif_aead")
	if !errors.Is(err, wantErr) {
		t.Fatalf("DryRunModule() error = %v, want errors.Is(_, %v)", err, wantErr)
	}

	want := kernelmod.DryRun{
		ResolvedTo: "install /bin/false",
		RawOutput:  "install /bin/false \n",
		Blocked:    true,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("DryRunModule() partial DryRun mismatch (-want +got):\n%s", diff)
	}
}
