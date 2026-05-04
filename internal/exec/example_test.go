// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"context"
	"errors"
	"fmt"
	"time"

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

// ExampleCmd shows the canonical Cmd construction: a logical Name
// (resolved through the allowlist), a typed Args slice mixing fixed
// flag constants (Trusted) and user-controlled values (Untrusted),
// and an explicit Timeout. The example does not invoke a Runner — it
// only documents the Cmd shape callers populate.
func ExampleCmd() {
	cmd := exec.Cmd{
		Name: "rpm",
		Args: []exec.Arg{
			exec.Trusted("-V"),
			exec.Untrusted("coreutils"),
		},
		Timeout: 10 * time.Second,
	}
	fmt.Println(cmd.Name, len(cmd.Args), cmd.Timeout)
	// Output:
	// rpm 2 10s
}

// ExampleNewOSRunner shows obtaining the production Runner. Production
// callers wire NewOSRunner once at startup and pass the Runner down
// through constructors, so test wiring (FakeRunner) can be substituted
// for unit testing of higher layers.
func ExampleNewOSRunner() {
	r := exec.NewOSRunner()
	if r == nil {
		fmt.Println("nil")
		return
	}
	fmt.Println("runner")
	// Output:
	// runner
}

// ExampleFakeRunner shows the canonical FakeRunner usage for unit
// tests of higher layers. Each entry in Responses is keyed by
// `Name + " " + each Arg.String() joined by space`, which is the same
// shape the production Runner sees; tests that build keys with this
// shape can drop in canned outputs without spawning a real subprocess.
func ExampleFakeRunner() {
	r := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"uname -r": {Stdout: []byte("6.1.0\n"), ExitCode: 0},
		},
	}
	res, err := r.Run(context.Background(), exec.Cmd{
		Name: "uname",
		Args: []exec.Arg{exec.Trusted("-r")},
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("stdout=%q exit=%d calls=%d\n", string(res.Stdout), res.ExitCode, len(r.Calls))
	// Output:
	// stdout="6.1.0\n" exit=0 calls=1
}

// ExampleNewRunnerForTest shows how internal-package tests drive the
// TestHelperProcess pattern: argv0 is the test binary, the prefix
// pre-pends the helper run flag and the "--" arg separator, and env
// carries the helper's behavior knobs. NOT for production use; the
// production constructor is NewOSRunner.
func ExampleNewRunnerForTest() {
	// Real tests pass os.Args[0] here; we use a placeholder for the
	// godoc example. This example does NOT invoke Run — it only
	// documents the constructor shape.
	r := exec.NewRunnerForTest(
		"/path/to/test/binary",
		[]string{"-test.run=TestHelperProcess", "--"},
		[]string{"GO_WANT_HELPER_PROCESS=1"},
	)
	if r != nil {
		fmt.Println("ok")
	}
	// Output:
	// ok
}
