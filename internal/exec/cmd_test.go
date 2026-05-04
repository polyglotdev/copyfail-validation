// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// helperRunner returns an exec.Runner that re-execs this test binary
// as the subprocess via TestHelperProcess. It exists so every test in
// this file exercises real syscalls (ProcessState, ExitCode, signal
// delivery) without depending on host-installed binaries.
//
// extraEnv is appended to the base helper env, letting per-test
// behavior knobs (GO_HELPER_BYTES, etc.) flow through without
// hard-coding a long base list.
func helperRunner(t *testing.T, behavior, text string, extraEnv ...string) exec.Runner {
	t.Helper()
	env := []string{
		"GO_WANT_HELPER_PROCESS=1",
		"GO_HELPER_BEHAVIOR=" + behavior,
		"GO_HELPER_TEXT=" + text,
		"PATH=" + os.Getenv("PATH"),
	}
	env = append(env, extraEnv...)
	return exec.NewRunnerForTest(os.Args[0], []string{"-test.run=TestHelperProcess", "--"}, env)
}

// TestCmd_Run_CapturesStdout pins the happy path: a subprocess that
// writes to stdout, exits 0, and the Runner captures the bytes
// verbatim. ExitCode is 0 and Truncated is false. This is the
// foundational test — every other case in the file builds on this
// roundtrip working.
func TestCmd_Run_CapturesStdout(t *testing.T) {
	t.Parallel()
	r := helperRunner(t, "echo-stdout", "hello world")
	res, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname", // logical name; testRunner ignores in re-exec mode
		Args:    []exec.Arg{exec.Trusted("-r")},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, want := string(res.Stdout), "hello world"; got != want {
		t.Errorf("Stdout = %q, want %q", got, want)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
	if res.Truncated {
		t.Errorf("Truncated = true, want false")
	}
	if res.Path == "" {
		t.Errorf("Path = empty, want non-empty (the test binary path)")
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %s, want > 0", res.Duration)
	}
}

// TestCmd_Run_CapturesStderr pins the symmetric case for stderr — the
// same wrapper plumbing must carry stderr verbatim, otherwise we would
// silently lose error messages from rpm/dpkg/debsums in production.
func TestCmd_Run_CapturesStderr(t *testing.T) {
	t.Parallel()
	r := helperRunner(t, "echo-stderr", "boom")
	res, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, want := string(res.Stderr), "boom"; got != want {
		t.Errorf("Stderr = %q, want %q", got, want)
	}
	if len(res.Stdout) != 0 {
		t.Errorf("Stdout = %q, want empty", res.Stdout)
	}
}

// TestCmd_Run_ForwardsArgsByteExact ensures the Runner does not quote,
// shell-escape, or otherwise mangle args between the parent and the
// subprocess. A regression here would mean the trust-boundary types
// no longer correspond to what actually reaches the binary, which
// would invalidate the whole security model.
func TestCmd_Run_ForwardsArgsByteExact(t *testing.T) {
	t.Parallel()
	r := helperRunner(t, "echo-args", "")
	res, err := r.Run(context.Background(), exec.Cmd{
		Name: "uname",
		Args: []exec.Arg{
			exec.Trusted("-V"),
			exec.Untrusted("util-linux-core-2.39.4-7.amzn2023.x86_64"),
		},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := "-V|util-linux-core-2.39.4-7.amzn2023.x86_64"
	if got := string(res.Stdout); got != want {
		t.Errorf("Stdout = %q, want %q", got, want)
	}
}

// TestCmd_Run_RejectsInvalidArgBeforeExec pins the security gate:
// when an Untrusted arg fails Validate, the Runner must return
// ErrInvalidArg WITHOUT spawning the subprocess. We verify by checking
// that the captured stderr is empty (the helper would have echoed
// GO_HELPER_TEXT to stderr if it had run) and that ExitCode is -1
// (process never started).
func TestCmd_Run_RejectsInvalidArgBeforeExec(t *testing.T) {
	t.Parallel()
	r := helperRunner(t, "echo-stderr", "should-not-appear")
	res, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{exec.Untrusted("foo;rm -rf /")},
		Timeout: 5 * time.Second,
	})
	if !errors.Is(err, exec.ErrInvalidArg) {
		t.Fatalf("err = %v, want errors.Is(_, ErrInvalidArg)", err)
	}
	if res.ExitCode != -1 {
		t.Errorf("ExitCode = %d, want -1 (process must not have started)", res.ExitCode)
	}
	if len(res.Stderr) != 0 {
		t.Errorf("Stderr = %q, want empty (subprocess must not have run)", res.Stderr)
	}
}

// TestCmd_Run_RejectsUntrustedFlagInjection is the targeted regression
// for the flag-injection vector. Even though "-rf" matches
// UntrustedArgRE character-wise, the leading-dash check rejects it.
// This test would fail if a future refactor combined the two checks
// into one and dropped the no-leading-dash rule.
func TestCmd_Run_RejectsUntrustedFlagInjection(t *testing.T) {
	t.Parallel()
	r := helperRunner(t, "echo-args", "")
	_, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{exec.Untrusted("-rf")},
		Timeout: 5 * time.Second,
	})
	if !errors.Is(err, exec.ErrInvalidArg) {
		t.Errorf("err = %v, want errors.Is(_, ErrInvalidArg)", err)
	}
}

// TestCmd_Run_TimesOut pins the timeout contract: a subprocess that
// outlasts Cmd.Timeout produces ErrTimeout. The 100 ms timeout against
// a select{}-blocked helper is short enough to be quick on CI but long
// enough to avoid a flaky race with very slow forkexec on a loaded
// runner.
func TestCmd_Run_TimesOut(t *testing.T) {
	t.Parallel()
	r := helperRunner(t, "sleep-forever", "")
	start := time.Now()
	_, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{},
		Timeout: 100 * time.Millisecond,
	})
	dur := time.Since(start)
	if !errors.Is(err, exec.ErrTimeout) {
		t.Fatalf("err = %v, want errors.Is(_, ErrTimeout)", err)
	}
	// Timeout should have actually fired around 100 ms; allow generous
	// upper bound for slow CI.
	if dur > 5*time.Second {
		t.Errorf("Run took %s, want close to the 100 ms timeout", dur)
	}
}

// TestCmd_Run_ParentContextCancel pins context propagation: canceling
// the parent context must kill the subprocess. This is the correctness
// test for chaining wrappers — if the parent does not propagate, then
// a higher-layer Run loop cannot abort outstanding subprocesses on
// SIGINT.
func TestCmd_Run_ParentContextCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	r := helperRunner(t, "sleep-forever", "")
	// Cancel after a short delay so the subprocess has time to start.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := r.Run(ctx, exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{},
		Timeout: 10 * time.Second, // give plenty of room so the cancel wins
	})
	dur := time.Since(start)
	if err == nil {
		t.Fatal("Run returned nil error, want error from canceled context")
	}
	if dur > 5*time.Second {
		t.Errorf("Run took %s, want close to the 50 ms cancel delay", dur)
	}
}

// TestCmd_Run_DefaultTimeoutApplied verifies the Cmd.Timeout==0
// fallback to DefaultTimeout. We use a helper that exits immediately
// so the test does not actually wait for DefaultTimeout — we just
// observe that no timeout error fires for a fast process.
func TestCmd_Run_DefaultTimeoutApplied(t *testing.T) {
	t.Parallel()
	r := helperRunner(t, "echo-stdout", "ok")
	res, err := r.Run(context.Background(), exec.Cmd{
		Name: "uname",
		Args: []exec.Arg{},
		// Timeout intentionally zero
	})
	if err != nil {
		t.Fatalf("Run with zero Timeout: %v", err)
	}
	if string(res.Stdout) != "ok" {
		t.Errorf("Stdout = %q, want %q", res.Stdout, "ok")
	}
}

// TestCmd_Run_PropagatesNonZeroExit pins the non-zero-exit contract:
// a subprocess that exits with a non-zero code returns an error AND
// populates Result.ExitCode with the actual code. Higher layers
// (integrity, kernelmod) inspect ExitCode to distinguish "package
// has been modified" (rpm -V exits 1) from "binary not found"
// (ErrCommandNotFound).
func TestCmd_Run_PropagatesNonZeroExit(t *testing.T) {
	t.Parallel()
	r := helperRunner(t, "exit-nonzero", "")
	res, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{},
		Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("err = nil, want non-nil for non-zero exit")
	}
	// Must NOT be ErrTimeout/ErrInvalidArg/etc — it's a generic exit
	// error; the contract is that ExitCode is set correctly.
	if errors.Is(err, exec.ErrTimeout) || errors.Is(err, exec.ErrInvalidArg) || errors.Is(err, exec.ErrOutputTruncated) {
		t.Errorf("err matched a sentinel inappropriately: %v", err)
	}
	if res.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2", res.ExitCode)
	}
}

// TestCmd_Run_TruncatesOversizedStdout pins the bounded-output
// contract: writes past MaxOutput are silently dropped, Truncated is
// set, and ErrOutputTruncated is returned. The test floods 2 MiB so
// the cap is decisively exceeded; we then verify the captured Stdout
// is exactly MaxOutput bytes.
func TestCmd_Run_TruncatesOversizedStdout(t *testing.T) {
	t.Parallel()
	const want = 2 * exec.MaxOutput
	r := helperRunner(t, "flood-stdout", "", "GO_HELPER_BYTES="+strconv.Itoa(want))
	res, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{},
		Timeout: 30 * time.Second,
	})
	if !errors.Is(err, exec.ErrOutputTruncated) {
		t.Fatalf("err = %v, want errors.Is(_, ErrOutputTruncated)", err)
	}
	if !res.Truncated {
		t.Errorf("Truncated = false, want true")
	}
	if len(res.Stdout) != exec.MaxOutput {
		t.Errorf("len(Stdout) = %d, want %d (MaxOutput)", len(res.Stdout), exec.MaxOutput)
	}
	for i, b := range res.Stdout {
		if b != 'x' {
			t.Errorf("Stdout[%d] = %q, want 'x' (every byte should be the helper's flood char)", i, b)
			break
		}
	}
}

// TestCmd_Run_TruncatesOversizedStderr pins the symmetric truncation
// case for stderr. Without this test, a future refactor could
// accidentally cap only stdout and leak unbounded stderr through a
// noisy debsums run.
func TestCmd_Run_TruncatesOversizedStderr(t *testing.T) {
	t.Parallel()
	const want = 2 * exec.MaxOutput
	r := helperRunner(t, "flood-stderr", "", "GO_HELPER_BYTES="+strconv.Itoa(want))
	res, err := r.Run(context.Background(), exec.Cmd{
		Name:    "uname",
		Args:    []exec.Arg{},
		Timeout: 30 * time.Second,
	})
	if !errors.Is(err, exec.ErrOutputTruncated) {
		t.Fatalf("err = %v, want errors.Is(_, ErrOutputTruncated)", err)
	}
	if !res.Truncated {
		t.Errorf("Truncated = false, want true")
	}
	if len(res.Stderr) != exec.MaxOutput {
		t.Errorf("len(Stderr) = %d, want %d (MaxOutput)", len(res.Stderr), exec.MaxOutput)
	}
}
