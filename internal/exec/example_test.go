// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"errors"
	"fmt"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// ExampleValidate_trusted shows that Trusted args bypass character
// validation entirely — the trust assertion is the caller's
// responsibility, recorded by their use of the Trusted type. This is
// the expected use for hard-coded flag constants like Trusted("-V").
func ExampleValidate_trusted() {
	// A Trusted value that contains shell metacharacters still
	// validates: the type itself is the security review.
	if err := exec.Validate(exec.Trusted("anything goes; rm -rf /")); err != nil {
		fmt.Println("unexpected:", err)
		return
	}
	fmt.Println("ok")
	// Output:
	// ok
}

// ExampleResolveCommand shows resolving a logical command name to an
// absolute path. uname is allowlisted on every supported host, so this
// example does not assert the exact path (which varies by OS) — only
// that resolution succeeds. A non-allowlisted name (e.g., "rm") would
// return ErrCommandDenied; a missing binary would return
// ErrCommandNotFound.
func ExampleResolveCommand() {
	path, err := exec.ResolveCommand("uname")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	if path != "" {
		fmt.Println("resolved")
	}
	// Output:
	// resolved
}

// ExampleValidate_untrusted shows the two failure modes for Untrusted
// values: characters outside UntrustedArgRE (here, a space — which is
// the most common shell-injection vector) and the leading-dash
// flag-injection guard.
func ExampleValidate_untrusted() {
	// Safe input.
	if err := exec.Validate(exec.Untrusted("algif_aead")); err == nil {
		fmt.Println("safe: ok")
	}

	// Shell metacharacter (space).
	if err := exec.Validate(exec.Untrusted("foo bar")); errors.Is(err, exec.ErrInvalidArg) {
		fmt.Println("metachar: rejected")
	}

	// Leading dash (flag injection).
	if err := exec.Validate(exec.Untrusted("--config=/etc/passwd")); errors.Is(err, exec.ErrInvalidArg) {
		fmt.Println("flag: rejected")
	}
	// Output:
	// safe: ok
	// metachar: rejected
	// flag: rejected
}
