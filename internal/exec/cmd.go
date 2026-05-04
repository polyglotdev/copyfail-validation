// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import "time"

// MaxOutput is the per-stream cap on captured stdout/stderr (1 MiB).
// When a stream exceeds this cap, excess bytes are quietly dropped
// (the subprocess keeps running so we do not SIGPIPE it via a closed
// pipe), Result.Truncated is set to true, and the Runner returns
// ErrOutputTruncated alongside the populated Result.
const MaxOutput = 1 << 20

// DefaultTimeout is applied when Cmd.Timeout is zero. Picked to be
// long enough for slow rpm/dpkg verifications on a busy host but short
// enough that a hung subprocess does not block the validator
// indefinitely.
const DefaultTimeout = 30 * time.Second

// Cmd describes one command to execute. The zero Cmd is invalid;
// callers MUST set Name and SHOULD set Timeout (default applies if
// zero).
type Cmd struct {
	// Name is the logical command name (e.g., "modprobe"). It is NOT a
	// path: the actual executable is resolved via ResolveCommand at
	// Run time, so the allowlist check happens on every call.
	Name string

	// Args are the command arguments. Each must be a Trusted or
	// Untrusted value (see arg.go). Untrusted args are validated
	// (UntrustedArgRE + leading-dash check) before exec; a failure
	// returns ErrInvalidArg without ever reaching the subprocess.
	Args []Arg

	// Env, if non-nil, replaces the inherited environment for the
	// subprocess. The default behavior (Env == nil) is a minimal env:
	// PATH (inherited from the parent so LookPath works) and LANG=C
	// (so locale-sensitive subprocess output stays parser-deterministic).
	Env []string

	// Timeout is the maximum wall-clock duration. Zero means
	// DefaultTimeout. The Runner cancels the underlying context when
	// the timeout fires; ErrTimeout is returned alongside whatever was
	// captured before the kill.
	Timeout time.Duration
}

// Result holds what a Runner.Run captured from one Cmd execution. A
// non-nil error from Run does not mean Result is empty — Stdout,
// Stderr, ExitCode, Path, and Duration are populated on a best-effort
// basis even when the subprocess failed, timed out, or was truncated,
// so callers can include the partial output in audit logs.
type Result struct {
	// Path is the resolved absolute path of the executable that ran
	// (whatever ResolveCommand returned). Recorded so audit trails can
	// distinguish /sbin/modprobe from /usr/sbin/modprobe.
	Path string

	// Stdout holds captured standard output, capped at MaxOutput bytes.
	// When the cap is hit, excess is dropped and Truncated is set to
	// true (and the Runner returns ErrOutputTruncated).
	Stdout []byte

	// Stderr holds captured standard error, with the same cap and
	// truncation semantics as Stdout.
	Stderr []byte

	// Duration is wall-clock time spent waiting for the subprocess,
	// measured from os/exec.Cmd.Start to os/exec.Cmd.Wait.
	Duration time.Duration

	// ExitCode is the subprocess exit code. -1 if the process did not
	// exit normally (signal, timeout-kill, or a fork/exec failure
	// before the process started).
	ExitCode int

	// Truncated is true when either Stdout or Stderr hit the MaxOutput
	// cap during this Run. The Runner also returns ErrOutputTruncated
	// in that case so callers using errors.Is do not have to inspect
	// the Result first.
	Truncated bool
}
