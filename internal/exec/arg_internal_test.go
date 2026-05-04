// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"errors"
	"testing"
)

// fakeArg is a third Arg implementation declared in the production
// package's test scope. The Arg interface is sealed via the unexported
// argSentinel method, which means external packages CANNOT add a third
// trust class — but a test file inside `package exec` can, in order to
// pin the default branch of Validate's type-switch.
//
// Without this test, the default branch is unreachable from any callable
// path (good — that's the seal working) and would silently rot. The test
// makes any future widening of the switch (or accidental removal of the
// default branch) immediately visible.
type fakeArg string

func (fakeArg) argSentinel()     {}
func (f fakeArg) String() string { return string(f) }

// TestValidateRejectsUnknownArgType guards the default branch of the
// type-switch in Validate. The Arg interface is sealed via the
// unexported argSentinel method, so this branch is unreachable from
// outside the package — this internal test is the only place it can
// be exercised. The branch exists as defense in depth: if the switch
// is ever refactored (e.g., split into separate functions), an
// unhandled Arg implementation must still produce ErrInvalidArg rather
// than silently passing.
func TestValidateRejectsUnknownArgType(t *testing.T) {
	t.Parallel()
	err := Validate(fakeArg("x"))
	if !errors.Is(err, ErrInvalidArg) {
		t.Errorf("Validate(fakeArg) = %v, want errors.Is(_, ErrInvalidArg)", err)
	}
}
