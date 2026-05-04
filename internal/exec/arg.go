// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package exec is the safe subprocess wrapper used by every higher
// internal/* package that shells out to a system binary. Its single
// purpose is to eliminate the shell-injection class of vulnerabilities
// from the rest of the codebase.
//
// The package never invokes a shell (sh, bash, or system()). It runs
// commands directly via os/exec with separated arg vectors. Each
// argument slot is statically typed as either Trusted or Untrusted via
// the sealed Arg interface, so the compiler enforces a security review
// at every call site that injects user-controlled data into a command
// line. Untrusted args must pass UntrustedArgRE and not start with '-',
// which prevents both metacharacter injection and flag injection.
//
// Scope of defense: this package defends against shell-injection-class
// problems only. It deliberately does NOT defend against path traversal,
// file overwrite, or resource exhaustion outside of its own subprocess
// timeout — those are the caller's responsibility because only the
// caller knows the domain semantics. See spec §7 for the full rationale.
package exec

import (
	"fmt"
	"regexp"
	"strings"
)

// Arg is the argument-slot type accepted by Cmd.Args. Concrete types
// are Trusted (bypasses character validation) and Untrusted (must pass
// UntrustedArgRE and not start with '-'). The interface is sealed via
// the unexported argSentinel method so external packages cannot add a
// third trust class without security review.
type Arg interface {
	argSentinel()

	// String returns the underlying string value. Used by Runner
	// implementations to materialize the os/exec arg vector.
	String() string
}

// Trusted is a string the caller asserts is safe — typically a
// hard-coded constant (a fixed flag like Trusted("-V")) or a value
// already validated by a domain-specific validator (e.g., a path
// cleaned and containment-checked by the --conf flag handler). Validate
// always returns nil for Trusted values; the trust assertion is the
// caller's responsibility, recorded by the use of this type.
type Trusted string

func (Trusted) argSentinel() {}

// String returns the underlying string value of t.
func (t Trusted) String() string { return string(t) }

// Untrusted is a string from a user-controlled source (a flag value, an
// environment variable, or subprocess output that will be re-fed to
// another subprocess). Untrusted values MUST pass Validate before being
// placed into a Cmd.Args slot; Cmd.Run / Runner.Run enforce this
// automatically and return ErrInvalidArg if validation fails.
type Untrusted string

func (Untrusted) argSentinel() {}

// String returns the underlying string value of u.
func (u Untrusted) String() string { return string(u) }

// UntrustedArgRE matches the conservative set of characters allowed in
// an Untrusted argument: alphanumerics, dot, underscore, hyphen, forward
// slash, plus, colon, equals, comma, at-sign. Length must be ≥ 1.
//
// The regex deliberately permits forward slash (legitimate values
// include package names like `util-linux-core-2.39.4-7.amzn2023.x86_64`
// and absolute paths) and does NOT block ".." segments — path-traversal
// defense belongs to the layer that knows path semantics; see spec §7.
//
// Leading "-" is rejected by a separate check in Validate to prevent
// flag injection (e.g., a positional argument value of "--config=/etc/passwd"
// being interpreted as a flag).
var UntrustedArgRE = regexp.MustCompile(`^[A-Za-z0-9._\-/+:=,@]+$`)

// Validate reports whether arg is acceptable for placement in Cmd.Args.
// Trusted args always pass (validation is the caller's responsibility,
// recorded by their use of the Trusted type). Untrusted args must:
//
//  1. match UntrustedArgRE (rejects shell metacharacters, NUL, newlines,
//     spaces, and any character outside the safe set);
//  2. not begin with '-' (flag-injection guard).
//
// Validate returns ErrInvalidArg (wrapped with detail) on failure so
// callers can match with errors.Is.
func Validate(arg Arg) error {
	switch a := arg.(type) {
	case Trusted:
		return nil
	case Untrusted:
		s := string(a)
		if !UntrustedArgRE.MatchString(s) {
			return fmt.Errorf("%w: %q (allowed pattern: %s)", ErrInvalidArg, s, UntrustedArgRE.String())
		}
		if strings.HasPrefix(s, "-") {
			return fmt.Errorf("%w: %q starts with '-' (flag-injection guard)", ErrInvalidArg, s)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown Arg type %T", ErrInvalidArg, arg)
	}
}
