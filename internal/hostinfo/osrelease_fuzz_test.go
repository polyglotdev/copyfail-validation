// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package hostinfo_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/hostinfo"
)

// FuzzParseOSRelease drives random + seeded inputs through the parser
// to flush out panics, infinite loops, and shape-contract violations.
// Properties asserted:
//
//  1. The parser never panics regardless of input.
//  2. The parser never returns a non-nil error for an input that does
//     not produce a Reader error (the only documented error path is a
//     transient I/O failure on the underlying io.Reader).
//  3. Empty (id, versionID, prettyName) is always a valid return shape
//     — no panic, no error, just empty strings.
//
// The corpus seeds with the three real distribution fixtures, an
// empty file, and a handful of adversarial strings (binary garbage,
// extreme whitespace, unbalanced quotes) so the fuzzer starts from
// inputs already known to exercise both the happy and error paths.
func FuzzParseOSRelease(f *testing.F) {
	for _, name := range []string{"os-release-al2023", "os-release-ubuntu2204", "os-release-rocky9"} {
		data, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- name is a hard-coded fixture filename in test code.
		if err != nil {
			f.Fatalf("read %s fixture: %v", name, err)
		}
		f.Add(string(data))
	}

	// Empty input is a documented happy-path case worth keeping in
	// the corpus so mutations near zero-length are explored.
	f.Add("")

	// Adversarial seeds that exercise edge cases.
	f.Add("\n\n\n")
	f.Add("    \t   ")
	f.Add("ID=\n")
	f.Add(`ID="`)          // unbalanced double-quote
	f.Add(`ID='`)          // unbalanced single-quote
	f.Add(`ID="a\` + "\n") // dangling backslash inside double quotes
	f.Add("ID=ubuntu\x00VERSION_ID=22.04")
	f.Add("\xff\xfe\xfd")                  // binary garbage
	f.Add(strings.Repeat("=value\n", 100)) // many empty-key lines
	f.Add(strings.Repeat("ID=ubuntu\n", 100))

	f.Fuzz(func(subT *testing.T, input string) {
		// The only documented error path is an io.Reader failure;
		// strings.NewReader never fails, so any error here is a bug.
		_, _, _, err := hostinfo.ParseOSRelease(strings.NewReader(input))
		if err != nil {
			subT.Fatalf("ParseOSRelease() unexpected error for input %q: %v", input, err)
		}
	})
}
