// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package kernelmod_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/kernelmod"
)

// FuzzParseProcModules drives random + seeded inputs through the parser
// to flush out panics, infinite loops, and shape-contract violations.
// Properties asserted:
//
//  1. The parser never panics regardless of input.
//  2. The result slice is always non-nil — callers can range over it
//     without a length check, even on the error path.
//  3. The (result, error) pair never both signal "nothing to report":
//     either we have rows (len(mods) > 0), or we have an error, or both.
//     A nil error with an empty slice IS valid (genuinely empty input)
//     and is allowed by this check.
//
// The corpus seeds with the real AL2023 fixture, the empty file, and a
// handful of adversarial strings (incomplete columns, garbage bytes,
// extreme whitespace) so the fuzzer starts from inputs already known to
// exercise both the happy and error paths.
func FuzzParseProcModules(f *testing.F) {
	// Seed with the real-world fixture so the fuzzer immediately
	// explores mutations of plausible /proc/modules data.
	al2023, err := os.ReadFile(filepath.Join("testdata", "procmodules-al2023.txt"))
	if err != nil {
		f.Fatalf("read AL2023 fixture: %v", err)
	}
	f.Add(string(al2023))

	algif, err := os.ReadFile(filepath.Join("testdata", "procmodules-with-algif.txt"))
	if err != nil {
		f.Fatalf("read algif fixture: %v", err)
	}
	f.Add(string(algif))

	// Empty input is a documented happy-path case worth keeping in
	// the corpus so mutations near zero-length are explored.
	f.Add("")

	// Adversarial seeds that exercise error paths and edge cases.
	f.Add("\n\n\n")
	f.Add("    \t   ")
	f.Add("malformed")
	f.Add("a b c")
	f.Add("a 1 1 - Live")
	f.Add("a NOT_A_NUM 0 - Live 0x0")
	f.Add("a 1 NOT_A_NUM - Live 0x0")
	f.Add("a -1 0 - Live 0x0")
	f.Add("a 1 0  Live 0x0")                         // empty usedby column from double space
	f.Add("a 1 0 ,, Live 0x0")                       // commas-only usedby
	f.Add("a 1 0 ,,, Live 0x0")                      // more commas
	f.Add("a 1 0 b,c,d Live 0x0\n\n")                // trailing blanks
	f.Add(strings.Repeat("a 1 0 - Live 0x0\n", 100)) // many lines

	f.Fuzz(func(subT *testing.T, input string) {
		mods, err := kernelmod.ParseProcModules(strings.NewReader(input))

		if mods == nil {
			subT.Fatalf("ParseProcModules() returned nil slice (must be non-nil); input=%q err=%v", input, err)
		}

		// "Nothing to report" check: if we returned no rows AND no
		// error, the input must have been empty-or-blank. If it
		// contained any non-whitespace byte we should have either
		// produced a row or an error — never both empty.
		if len(mods) == 0 && err == nil {
			if strings.TrimSpace(input) != "" {
				subT.Fatalf("ParseProcModules() returned 0 modules and nil error for non-blank input %q", input)
			}
		}
	})
}
