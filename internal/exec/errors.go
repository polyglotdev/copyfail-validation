// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import "errors"

// Sentinel errors returned by this package. Callers MUST match with
// errors.Is rather than string comparison — error messages are not part
// of the package's API contract and may change between minor releases.
var (
	// ErrCommandNotFound is returned when the requested command name is
	// allowlisted but neither the preferred absolute path exists nor
	// os/exec.LookPath can find an alternative on $PATH.
	ErrCommandNotFound = errors.New("exec: command not found")

	// ErrCommandDenied is returned when the requested command name is not
	// in allowedCommands. This is distinct from ErrCommandNotFound: the
	// binary may exist on $PATH but is not on the allowlist, and adding a
	// new entry requires a security review (see allowlist.go for the rule).
	ErrCommandDenied = errors.New("exec: command not on allowlist")

	// ErrInvalidArg is returned when an Untrusted arg fails Validate
	// (either it contains characters outside UntrustedArgRE, starts with
	// '-', is empty, or is an unknown Arg implementation).
	ErrInvalidArg = errors.New("exec: invalid argument")

	// ErrTimeout is returned when the per-Cmd Timeout fires before the
	// subprocess completes. The Result is still populated with whatever
	// stdout/stderr/exit-code were captured before the kill.
	ErrTimeout = errors.New("exec: command timed out")

	// ErrOutputTruncated is returned (in addition to populating
	// Result.Truncated = true) when stdout or stderr exceeded MaxOutput
	// bytes. The truncated bytes are still in the Result so callers can
	// inspect what was captured before the cap was hit.
	ErrOutputTruncated = errors.New("exec: output truncated")
)
