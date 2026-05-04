// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is the os/exec stdlib pattern for testing
// subprocess wrappers without depending on host binaries. It runs only
// when GO_WANT_HELPER_PROCESS=1 is set in the environment, in which
// case it dispatches on GO_HELPER_BEHAVIOR and calls os.Exit before
// returning so the test framework never sees the helper "test" itself.
//
// IMPORTANT: We deliberately do NOT call t.Helper() here, and we do
// NOT use `defer os.Exit(...)`. Both would let the testing package
// observe a partially-completed test and then panic on the
// "unexpected call to os.Exit" trap (introduced in Go 1.16+). The
// stdlib os/exec pattern is to call os.Exit directly from each branch.
//
// Behaviors:
//
//   - "echo-stdout": print GO_HELPER_TEXT to stdout, exit 0.
//   - "echo-stderr": print GO_HELPER_TEXT to stderr, exit 0.
//   - "exit-nonzero": exit 2 (no output).
//   - "sleep-forever": time.Sleep for an hour (effectively forever)
//     until the parent kills the subprocess. NOTE: we do NOT use
//     `select {}` here because this test runs as a goroutine inside
//     the test binary, and an empty select traps the runtime's
//     deadlock detector — which exits 2 BEFORE the parent's timeout
//     fires, so the parent sees a normal exit-2 instead of a kill.
//     time.Sleep is goroutine-safe and triggers no deadlock check.
//   - "flood-stdout": write GO_HELPER_BYTES bytes of 'x' to stdout.
//   - "flood-stderr": write GO_HELPER_BYTES bytes of 'y' to stderr.
//   - "echo-args": print os.Args[1:] joined by '|', exit 0. Used to
//     verify args reach the subprocess byte-exact (no quoting or
//     mangling by the wrapper).
//
// This test does NOT exercise the package directly; it is the
// subprocess side of the contract. The parent side lives in cmd_test.go.
func TestHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	switch os.Getenv("GO_HELPER_BEHAVIOR") {
	case "echo-stdout":
		_, _ = fmt.Fprint(os.Stdout, os.Getenv("GO_HELPER_TEXT"))
	case "echo-stderr":
		_, _ = fmt.Fprint(os.Stderr, os.Getenv("GO_HELPER_TEXT"))
	case "exit-nonzero":
		os.Exit(2)
	case "sleep-forever":
		time.Sleep(time.Hour)
	case "flood-stdout":
		flood(os.Stdout, 'x')
	case "flood-stderr":
		flood(os.Stderr, 'y')
	case "echo-args":
		// os.Args layout: [helper-binary, -test.run=..., --, <user args>...]
		// The "--" separator is supplied by NewRunnerForTest; everything
		// after it is what the parent passed as cmd.Args.
		var userArgs []string
		seenSep := false
		for _, a := range os.Args[1:] {
			if seenSep {
				userArgs = append(userArgs, a)
				continue
			}
			if a == "--" {
				seenSep = true
			}
		}
		_, _ = fmt.Fprint(os.Stdout, strings.Join(userArgs, "|"))
	}
	os.Exit(0)
}

// flood writes GO_HELPER_BYTES bytes of b to w. Used by the truncation
// tests to push past MaxOutput. If the env var is unset or unparsable,
// flood writes nothing — the parent test will then assert no truncation.
func flood(w io.Writer, b byte) {
	n, err := strconv.Atoi(os.Getenv("GO_HELPER_BYTES"))
	if err != nil || n <= 0 {
		return
	}
	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = b
	}
	for written := 0; written < n; {
		toWrite := len(chunk)
		if remaining := n - written; remaining < toWrite {
			toWrite = remaining
		}
		nWritten, werr := w.Write(chunk[:toWrite])
		written += nWritten
		if werr != nil {
			return
		}
	}
}
