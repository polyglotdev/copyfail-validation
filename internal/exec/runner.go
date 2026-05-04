// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"strings"
	"time"
)

// Runner executes a Cmd. The package ships three implementations:
//
//   - osRunner (returned by NewOSRunner) — production. Resolves the
//     command via ResolveCommand, validates Untrusted args, applies
//     the timeout, runs via os/exec, captures bounded stdout/stderr.
//
//   - testRunner (returned by NewRunnerForTest) — re-execs the test
//     binary with sentinel env vars to drive the TestHelperProcess
//     pattern from os/exec's own tests. Lets us exercise real syscalls
//     in CI without depending on host binaries.
//
//   - FakeRunner — pure-Go map-of-canned-responses for unit tests of
//     higher layers (kernelmod, integrity, procscan). Records every
//     Cmd it received so tests can assert on exact call shape.
type Runner interface {
	// Run executes cmd under ctx and returns the captured Result. The
	// Result is populated on a best-effort basis even when the returned
	// error is non-nil (timeouts, truncation, non-zero exits all leave
	// usable partial output for audit logs).
	Run(ctx context.Context, cmd Cmd) (Result, error)
}

// NewOSRunner returns the production Runner, which uses os/exec and
// runs commands resolved via the package allowlist.
func NewOSRunner() Runner { return osRunner{} }

// NewRunnerForTest returns a Runner that always invokes argv0 with
// prefixedArgs followed by the stringified Cmd.Args, using the supplied
// env. This drives the TestHelperProcess pattern from os/exec; it is
// NOT for production use. argv0 is typically os.Args[0] (the test
// binary itself); prefixedArgs is typically `{"-test.run=TestHelperProcess", "--"}`.
func NewRunnerForTest(argv0 string, prefixedArgs, env []string) Runner {
	return &testRunner{argv0: argv0, prefix: prefixedArgs, env: env}
}

// FakeRunner returns canned Results from the Responses map (keyed by
// `cmd.Name + " " + strings.Join(args, " ")`) and records every Cmd it
// received in Calls. If neither Responses nor Errors has a registered
// entry for a key, Run returns an error so unmocked calls in tests
// fail loudly instead of silently returning the zero Result.
//
// FakeRunner is safe for sequential use only — Calls is appended to
// without locking. Higher-layer tests typically run a single Runner
// per t.Run subtest, so this matches their expected usage.
type FakeRunner struct {
	// Responses maps a key (see fakeKey) to the Result the Runner
	// should return. The error returned alongside is nil unless the
	// same key also appears in Errors.
	Responses map[string]Result

	// Errors maps a key to the error the Runner should return. When a
	// key appears in Errors, the corresponding Result from Responses
	// (if any) is still returned — this lets tests express both a
	// non-zero exit and a partial output capture.
	Errors map[string]error

	// Calls records every Cmd handed to Run, in order, so tests can
	// assert on exact Name + Args (including Trusted/Untrusted typing).
	Calls []Cmd
}

// Run records cmd, then returns the registered Response/Error for the
// key derived from cmd. If neither map has the key, Run returns an
// error so unmocked calls in tests fail loudly.
func (f *FakeRunner) Run(_ context.Context, cmd Cmd) (Result, error) {
	f.Calls = append(f.Calls, cmd)
	key := fakeKey(cmd)
	res, hasRes := f.Responses[key]
	err, hasErr := f.Errors[key]
	switch {
	case hasErr && hasRes:
		return res, err
	case hasErr:
		return Result{}, err
	case hasRes:
		return res, nil
	default:
		return Result{}, fmt.Errorf("FakeRunner: no canned response for key %q", key)
	}
}

// fakeKey is the canonical lookup key for FakeRunner.Responses and
// FakeRunner.Errors. It is `cmd.Name` followed by each arg joined by
// single spaces. Tests build matching keys with the same shape.
func fakeKey(cmd Cmd) string {
	parts := make([]string, 0, 1+len(cmd.Args))
	parts = append(parts, cmd.Name)
	for _, a := range cmd.Args {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, " ")
}

// osRunner is the production Runner.
type osRunner struct{}

// Run resolves cmd.Name through the allowlist, validates Untrusted args,
// applies the timeout, and runs the subprocess with a minimal env by
// default (see Cmd.Env).
func (osRunner) Run(ctx context.Context, cmd Cmd) (Result, error) {
	path, resolveErr := ResolveCommand(cmd.Name)
	if resolveErr != nil {
		return Result{ExitCode: -1}, resolveErr
	}
	if validateErr := validateAll(cmd.Args); validateErr != nil {
		return Result{Path: path, ExitCode: -1}, validateErr
	}
	args := stringifyArgs(cmd.Args)
	env := cmd.Env
	if env == nil {
		env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C"}
	}
	return runProcess(ctx, path, args, env, cmdTimeout(cmd))
}

// testRunner re-execs the test binary with sentinel env vars to
// simulate a subprocess. Args from cmd are validated identically to
// osRunner so tests exercise the same validation path.
type testRunner struct {
	argv0  string
	prefix []string
	env    []string
}

// Run validates Untrusted args, then invokes argv0 with prefix ++
// stringified cmd.Args under the test env.
func (t *testRunner) Run(ctx context.Context, cmd Cmd) (Result, error) {
	if validateErr := validateAll(cmd.Args); validateErr != nil {
		return Result{Path: t.argv0, ExitCode: -1}, validateErr
	}
	stringified := stringifyArgs(cmd.Args)
	args := make([]string, 0, len(t.prefix)+len(stringified))
	args = append(args, t.prefix...)
	args = append(args, stringified...)
	return runProcess(ctx, t.argv0, args, t.env, cmdTimeout(cmd))
}

// validateAll runs Validate over every Arg in args and returns the
// first error (wrapping ErrInvalidArg).
func validateAll(args []Arg) error {
	for _, a := range args {
		if err := Validate(a); err != nil {
			return err
		}
	}
	return nil
}

// stringifyArgs materializes the os/exec arg vector. The args have
// already passed Validate at this point — stringifyArgs is a thin
// helper that exists to keep the conversion in one place.
func stringifyArgs(args []Arg) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, a.String())
	}
	return out
}

// cmdTimeout returns the effective timeout for cmd, applying
// DefaultTimeout when cmd.Timeout is zero.
func cmdTimeout(cmd Cmd) time.Duration {
	if cmd.Timeout <= 0 {
		return DefaultTimeout
	}
	return cmd.Timeout
}

// runProcess is the shared exec path used by osRunner and testRunner.
// It owns the timeout context, the cappedBuffer plumbing, and the
// error-classification rules so both Runners surface identical
// semantics for timeouts, truncation, non-zero exits, and exec
// failures.
func runProcess(parent context.Context, path string, args, env []string, timeout time.Duration) (Result, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	stdout := &cappedBuffer{cap: MaxOutput}
	stderr := &cappedBuffer{cap: MaxOutput}

	c := osexec.CommandContext(ctx, path, args...)
	c.Env = env
	c.Stdout = stdout
	c.Stderr = stderr

	start := time.Now()
	runErr := c.Run()
	dur := time.Since(start)

	// Detach the captured bytes from the cappedBuffer's internal slice
	// so callers may freely mutate Result.Stdout / Result.Stderr without
	// aliasing back into the now-orphaned buffer (and so a future
	// cappedBuffer pool refactor cannot silently introduce a data race).
	res := Result{
		Path:      path,
		Stdout:    append([]byte(nil), stdout.bytes...),
		Stderr:    append([]byte(nil), stderr.bytes...),
		Duration:  dur,
		Truncated: stdout.truncated || stderr.truncated,
		ExitCode:  -1,
	}
	if c.ProcessState != nil {
		res.ExitCode = c.ProcessState.ExitCode()
	}

	// Timeout takes priority over a generic "exit error", because a
	// killed process surfaces both: ctx.Err() is the more informative
	// classification for callers using errors.Is.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return res, fmt.Errorf("%w: after %s", ErrTimeout, dur)
	}

	// When a subprocess BOTH truncates output AND exits non-zero, the
	// caller needs to be able to detect both conditions via errors.Is.
	// errors.Join (Go 1.20+) lets us return a multi-error so that
	//   errors.Is(err, ErrOutputTruncated)  AND
	//   errors.Is(err, &exec.ExitError{...})
	// both succeed. Without this, the truncation sentinel would be
	// silently shadowed by the exit error and operators would only
	// see Result.Truncated by inspecting the Result manually.
	if runErr != nil {
		wrapped := fmt.Errorf("exec %s: %w", path, runErr)
		if res.Truncated {
			return res, errors.Join(ErrOutputTruncated, wrapped)
		}
		return res, wrapped
	}

	if res.Truncated {
		return res, ErrOutputTruncated
	}

	return res, nil
}

// cappedBuffer is an io.Writer that stops collecting after cap bytes.
// Writes past the cap report as fully consumed (so the subprocess does
// not see an io.ErrShortWrite and SIGPIPE-out before producing the rest
// of its output) but truncated is set so the caller can see the cap was
// hit.
type cappedBuffer struct {
	bytes     []byte
	cap       int
	truncated bool
}

// Write appends as many bytes from p as fit under the cap, drops the
// rest, and returns len(p) so the subprocess never sees an
// io.ErrShortWrite. truncated is set on the first overflow.
func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.truncated {
		return len(p), nil
	}
	remaining := b.cap - len(b.bytes)
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.bytes = append(b.bytes, p[:remaining]...)
		b.truncated = true
		return len(p), nil
	}
	b.bytes = append(b.bytes, p...)
	return len(p), nil
}

// Compile-time assertion that cappedBuffer satisfies io.Writer.
var _ io.Writer = (*cappedBuffer)(nil)
