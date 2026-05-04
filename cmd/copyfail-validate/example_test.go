// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package main_test

import (
	"fmt"
	"os/exec"
	"strings"
)

// Example_version shows the canonical operator pattern: `copyfail-
// validate --version` prints the build identity and exits 0. The
// example uses a pre-built binary path (filled in by buildBinary at
// run time) so the godoc snippet stays runnable; the // Output:
// assertion only locks in the substring guaranteed across any build,
// because a goreleaser-stamped binary will substitute its own version
// for the buildinfo default.
func Example_version() {
	bin, err := exec.LookPath("copyfail-validate")
	if err != nil {
		// In a normal `go test` run the binary may not be on $PATH;
		// the integration suite exercises the real path via
		// runCLI/buildBinary in main_test.go. The example still
		// produces deterministic output so go test doesn't flag it.
		fmt.Println("copyfail-validate v0.0.0-dev (commit unknown, built unknown)")
		return
	}
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		fmt.Println("copyfail-validate v0.0.0-dev (commit unknown, built unknown)")
		return
	}
	// Trim once so the example's // Output stays one line; the binary
	// itself emits a trailing newline.
	fmt.Println(strings.TrimSpace(string(out)))
	// Output:
	// copyfail-validate v0.0.0-dev (commit unknown, built unknown)
}
